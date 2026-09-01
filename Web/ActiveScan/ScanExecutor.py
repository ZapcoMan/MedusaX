#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""扫描执行器

并发模型说明：
    Celery worker 使用 --pool=solo 运行，为避免与进程池嵌套产生冲突，
    扫描任务内部采用线程池执行 HTTP 探测（IO密集型场景线程池更合适）。

SQLite 写入策略：
    扫描线程只负责探测并把命中结果放入线程安全队列，
    由单一的写入线程批量落库，规避 SQLite 写锁竞争导致的
    "database is locked" 错误。
"""
import queue
import threading
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

from ClassCongregation import ErrorLog, VulnerabilityDetails
from Web.DatabaseHub import AgentHeader
from Web.ActiveScan.PluginEngine import PluginEngine
from Web.ActiveScan.ExpressionEvaluator import ExpressionEvaluator, ResponseContext

# requests 关闭冗余的证书告警输出
try:
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass

DEFAULT_TIMEOUT = 15  # 单个请求超时时间(秒)
MAX_BATCH_SIZE = 50  # 批量入库阈值


class ScanResult:  # 单条命中结果
    def __init__(self, url, plugin, response, request):
        self.url = url
        self.plugin = plugin
        self.response = response
        self.request = request


class ScanExecutor:
    """主动扫描执行器"""

    def __init__(self, url: str, active_scan_id: str, uid: str, process: int = 5,
                 module: str = "all", header=None, proxies: str = ""):
        self.url = url
        self.active_scan_id = active_scan_id
        self.uid = uid
        self.process = self._NormalizeProcess(process)
        self.module = module or "all"
        self.custom_header = header if isinstance(header, dict) else {}
        self.proxies = proxies
        self.result_queue = queue.Queue()
        self.evaluator = ExpressionEvaluator()
        self.engine = PluginEngine()
        self.total = 0
        self.finished = 0
        self.hit_count = 0
        self._writer_stop = object()  # 写入线程的停止哨兵

    @staticmethod
    def _NormalizeProcess(process) -> int:
        """规范化线程数，避免非法值导致资源耗尽"""
        try:
            value = int(process)
        except (TypeError, ValueError):
            return 5
        if value < 1:
            return 1
        return min(value, 50)

    def _BuildProxies(self) -> dict or None:
        """构造 requests 代理配置"""
        if not self.proxies:
            return None
        return {"http": self.proxies, "https": self.proxies}

    def _BuildHeaders(self) -> dict:
        """构造请求头，用户自定义头优先于默认随机头"""
        headers = {}
        try:
            headers["User-Agent"] = AgentHeader().result()
        except Exception:
            headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) MedusaX"
        for key, value in self.custom_header.items():
            headers[str(key)] = str(value)
        return headers

    @staticmethod
    def _JoinUrl(base: str, path: str) -> str:
        """拼接目标URL与插件路径"""
        base = (base or "").rstrip("/")
        if not path:
            return base
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if not path.startswith("/"):
            path = "/" + path
        return base + path

    def _Send(self, plugin, session, timeout=DEFAULT_TIMEOUT):
        """执行单条插件规则对应的请求，失败时返回 None"""
        url = self._JoinUrl(self.url, plugin.path)
        headers = self._BuildHeaders()
        for key, value in (plugin.headers or {}).items():
            headers[str(key)] = str(value)
        try:
            response = session.request(
                method=plugin.method,
                url=url,
                headers=headers,
                data=plugin.body if plugin.body else None,
                timeout=timeout,
                verify=False,
                allow_redirects=bool(plugin.follow_redirects),
                proxies=self._BuildProxies(),
            )
            return response
        except Exception as e:
            ErrorLog().Write("插件请求失败 %s -> %s : %s" % (plugin.method, url, e))
            return None

    def _ExecutePlugin(self, plugin_info, session):
        """执行一个插件的全部规则，命中则把结果放入队列"""
        last_response = None
        last_request = None
        try:
            for rule in plugin_info.rules:
                response = self._Send(rule, session)
                if response is None:
                    return  # 请求失败直接放弃该插件
                last_response = response
                last_request = response.request
                ctx = ResponseContext(response.status_code, response.content,
                                      dict(response.headers), response.url)
                if not self.evaluator.evaluate(rule.expression, ctx):
                    return  # 前序规则未命中则终止该插件
            # 全部规则通过视为命中
            self.result_queue.put(ScanResult(self.url, plugin_info, last_response, last_request))
        except Exception as e:
            ErrorLog().Write("插件执行异常 %s : %s" % (plugin_info.name, e))
        finally:
            self.finished += 1

    def _WriterLoop(self):
        """独立的写入线程，串行批量落库"""
        batch = []
        while True:
            item = self.result_queue.get()
            if item is self._writer_stop:
                break
            batch.append(item)
            if len(batch) >= MAX_BATCH_SIZE:
                self._Flush(batch)
                batch = []
            self.result_queue.task_done()
        if batch:
            self._Flush(batch)

    def _Flush(self, batch):
        """把一批命中结果写入 Medusa 表"""
        for item in batch:
            try:
                self._WriteOne(item)
                self.hit_count += 1
            except Exception as e:
                ErrorLog().Write("漏洞写入失败: %s" % e)

    def _WriteOne(self, item: ScanResult):
        """写入单条漏洞，同时写入 ScanInformation 关系表"""
        plugin = item.plugin
        medusa = {
            "name": plugin.name,
            "number": _ExtractCve(plugin.name, plugin.detail),
            "author": plugin.Author(),
            "create_date": time.strftime("%Y-%m-%d", time.localtime()),
            "algroup": plugin.name,
            "rank": _NormalizeRank(plugin.detail),
            "disclosure": str(plugin.detail.get("disclosure", "") or plugin.detail.get("Disclosure", "") or ""),
            "details": _BuildDetails(item),
            "affects": str(plugin.detail.get("affects", "") or plugin.name),
            "desc_content": str(plugin.detail.get("desc_content", "")
                                or plugin.detail.get("description", "")
                                or plugin.AffectedVersion()),
            "suggest": str(plugin.detail.get("suggest", "") or plugin.detail.get("recommendation", "") or ""),
            "version": plugin.AffectedVersion(),
        }
        VulnerabilityDetails(medusa, item.response, Url=item.url, Uid=self.uid,
                             ActiveScanId=self.active_scan_id).Write()

    def run(self) -> dict:
        """执行扫描，返回统计信息"""
        plugins = self.engine.LoadByModule(self.module)
        self.total = len(plugins)
        if self.total == 0:
            return {"total": 0, "hit": 0, "message": "未匹配到任何可用插件"}

        writer = threading.Thread(target=self._WriterLoop, name="ScanWriter")
        writer.start()

        session = requests.Session()
        try:
            with ThreadPoolExecutor(max_workers=self.process) as pool:
                futures = [pool.submit(self._ExecutePlugin, p, session) for p in plugins]
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        ErrorLog().Write("扫描任务异常: %s" % e)
        finally:
            self.result_queue.put(self._writer_stop)
            writer.join()

        return {"total": self.total, "hit": self.hit_count, "message": "扫描完成"}


def _ExtractCve(name: str, detail: dict) -> str:
    """从插件名或详情中提取 CVE 编号"""
    import re
    text = "%s %s" % (name, detail or {})
    match = re.search(r"(CVE-\d{4}-\d+)", text, re.I)
    return match.group(1).upper() if match else ""


def _NormalizeRank(detail: dict) -> str:
    """规范化漏洞等级"""
    rank = str(detail.get("rank", "") or detail.get("level", "") or "").strip()
    mapping = {
        "critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息",
        "严重": "严重", "高危": "高危", "中危": "中危", "低危": "低危", "信息": "信息",
    }
    return mapping.get(rank.lower(), "高危" if not rank else rank)


def _BuildDetails(item: ScanResult) -> str:
    """构造漏洞详情文本，包含请求与响应摘要"""
    plugin = item.plugin
    lines = []
    lines.append("目标: %s" % item.url)
    if item.response is not None:
        lines.append("请求地址: %s" % getattr(item.response.request, "url", ""))
        lines.append("请求方法: %s" % getattr(item.response.request, "method", ""))
        lines.append("响应状态码: %s" % item.response.status_code)
    lines.append("影响版本: %s" % plugin.AffectedVersion())
    links = plugin.Links()
    if links:
        lines.append("参考链接:")
        lines.append(links)
    return "\n".join(lines)
