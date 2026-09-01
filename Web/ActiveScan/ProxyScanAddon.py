#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""被动扫描代理插件（mitmproxy addon）

拦截流经代理的 HTTP 流量，完成两件事：
    1. 原始流量留存到 OriginalProxyData 表，供前端查看与后续分析
    2. 对流量调用插件引擎做被动漏洞检测

代理认证：通过 Proxy-Authorization 头中的用户名密码匹配 ProxyScanList 表，
将流量归属到对应的用户与项目。
"""
import base64
import time

from ClassCongregation import ErrorLog
from Web.DatabaseHub import OriginalProxyData, ProxyScanList
from Web.ActiveScan.ScanExecutor import ScanExecutor
from Web.ActiveScan.PluginEngine import PluginEngine


def ParseProxyAuth(headers) -> tuple:
    """从请求头中解析代理账号密码，返回 (username, password)"""
    try:
        raw = headers.get("Proxy-Authorization", "")
        if not raw or not raw.startswith("Basic "):
            return "", ""
        decoded = base64.b64decode(raw.split(" ", 1)[1]).decode("utf-8", "ignore")
        if ":" in decoded:
            username, password = decoded.split(":", 1)
            return username, password
        return decoded, ""
    except Exception:
        return "", ""


class PassiveScanAddon:
    """mitmproxy 的 addon 实现"""

    def __init__(self):
        self.engine = PluginEngine()
        self.plugins = self.engine.LoadAll()
        ErrorLog().Write("被动扫描代理已加载插件数量: %d" % len(self.plugins))

    def request(self, flow):
        """请求阶段：记录请求信息，不做阻断"""
        try:
            flow.request.headers.pop("Proxy-Authorization", None)  # 避免代理凭据被转发到目标站点
        except Exception:
            pass

    def response(self, flow):
        """响应阶段：留存流量并执行被动检测"""
        try:
            username, password = ParseProxyAuth(flow.request.headers)
            auth = ProxyScanList().ProxyAuthentication(proxy_username=username,
                                                       proxy_password=password)
            if not auth:
                return  # 未通过代理认证的数据不记录

            uid = auth.get("uid")
            proxy_id = auth.get("proxy_id")
            url = flow.request.pretty_url

            OriginalProxyData().Write(
                uid=uid,
                proxy_id=proxy_id,
                url=url,
                request_headers=str(dict(flow.request.headers)),
                request_date=str(flow.request.content or b""),
                request_method=str(flow.request.method),
                response_headers=str(dict(flow.response.headers)),
                response_status_code=str(flow.response.status_code),
                response_date_bytes=str(flow.response.content or b""),
                response_date_string=str(flow.response.text or ""),
                redis_id="",
            )
            self._PassiveDetect(uid, proxy_id, url, flow)
        except Exception as e:
            ErrorLog().Write("被动扫描处理失败: %s" % e)

    def _PassiveDetect(self, uid, proxy_id, url, flow):
        """对响应做被动漏洞检测"""
        if not self.plugins:
            return
        try:
            from Web.ActiveScan.ExpressionEvaluator import ResponseContext
            evaluator_ctx = ResponseContext(
                flow.response.status_code,
                flow.response.content or b"",
                dict(flow.response.headers),
                url,
            )
            from Web.ActiveScan.ExpressionEvaluator import ExpressionEvaluator
            evaluator = ExpressionEvaluator()
            for plugin in self.plugins:
                for rule in plugin.rules:
                    try:
                        if evaluator.evaluate(rule.expression, evaluator_ctx):
                            self._SavePassiveVuln(uid, proxy_id, url, plugin, flow)
                            break
                    except Exception as e:
                        ErrorLog().Write("被动检测插件异常 %s: %s" % (plugin.name, e))
        except Exception as e:
            ErrorLog().Write("被动检测执行失败: %s" % e)

    def _SavePassiveVuln(self, uid, proxy_id, url, plugin, flow):
        """保存被动检测命中的漏洞"""
        try:
            from ClassCongregation import VulnerabilityDetails
            from Web.ActiveScan.ScanExecutor import _ExtractCve, _NormalizeRank, _BuildDetails
            import requests

            # 构造一个轻量响应对象以复用统一写入逻辑
            response = requests.Response()
            response.status_code = flow.response.status_code
            response._content = flow.response.content or b""
            response.headers.update(dict(flow.response.headers))
            response.url = url
            response.request = requests.Request(
                method=flow.request.method, url=url,
                headers=dict(flow.request.headers),
                data=flow.request.content or b"",
            ).prepare()

            medusa = {
                "name": plugin.name,
                "number": _ExtractCve(plugin.name, plugin.detail),
                "author": plugin.Author(),
                "create_date": time.strftime("%Y-%m-%d", time.localtime()),
                "algroup": plugin.name,
                "rank": _NormalizeRank(plugin.detail),
                "disclosure": "",
                "details": _BuildDetails(_PassiveResult(url, plugin, response)),
                "affects": str(plugin.detail.get("affects", "") or plugin.name),
                "desc_content": str(plugin.detail.get("description", "") or plugin.AffectedVersion()),
                "suggest": str(plugin.detail.get("suggest", "") or ""),
                "version": plugin.AffectedVersion(),
            }
            # 被动扫描没有主动扫描任务ID，使用代理项目ID作为归属标识
            VulnerabilityDetails(medusa, response, Url=url, Uid=uid,
                                 ActiveScanId="PASSIVE-%s" % proxy_id).Write()
        except Exception as e:
            ErrorLog().Write("被动漏洞写入失败: %s" % e)


class _PassiveResult:  # 供 _BuildDetails 复用的轻量结果对象
    def __init__(self, url, plugin, response):
        self.url = url
        self.plugin = plugin
        self.response = response
