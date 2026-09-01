#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""扫描相关异步任务

所有耗时扫描均在 Celery worker 中异步执行，避免阻塞接口响应。
任务执行完成后会更新 ActiveScanList 表中的任务状态。
"""
from celery import shared_task

from ClassCongregation import ErrorLog
from Web.DatabaseHub import ActiveScanList
from Web.ActiveScan.ScanExecutor import ScanExecutor
from Web.ActiveScan.PortScan import PortScan
from Web.ActiveScan.SubdomainScan import SubdomainScan


def _FinishTask(redis_id):
    """标记任务完成"""
    try:
        ActiveScanList().UpdateStatus(redis_id=str(redis_id))
    except Exception as e:
        ErrorLog().Write("更新扫描任务状态失败: %s" % e)


@shared_task(bind=True, name="Web.ActiveScan.ScanTasks.ActiveScanTask")
def ActiveScanTask(self, url, active_scan_id, uid, process=5, module="all", header=None, proxies=""):
    """主动扫描主任务：加载插件对目标执行漏洞检测"""
    try:
        executor = ScanExecutor(url=url, active_scan_id=str(active_scan_id), uid=uid,
                                process=process, module=module, header=header, proxies=proxies)
        result = executor.run()
        ErrorLog().Write("主动扫描完成 target=%s 插件总数=%s 命中=%s"
                         % (url, result.get("total"), result.get("hit")))
        return result
    except Exception as e:
        ErrorLog().Write("主动扫描任务异常: %s" % e)
        return {"total": 0, "hit": 0, "message": "扫描任务异常"}
    finally:
        _FinishTask(self.request.id)


@shared_task(name="Web.ActiveScan.ScanTasks.PortScanTask")
def PortScanTask(url, active_scan_id, uid, port_argument=""):
    """端口扫描子任务"""
    try:
        scanner = PortScan(url=url, active_scan_id=str(active_scan_id), uid=uid,
                           port_argument=port_argument)
        result = scanner.run()
        ErrorLog().Write("端口扫描完成 target=%s 开放端口=%s" % (url, result.get("open")))
        return result
    except Exception as e:
        ErrorLog().Write("端口扫描任务异常: %s" % e)
        return {"total": 0, "open": 0, "message": "端口扫描异常"}


@shared_task(name="Web.ActiveScan.ScanTasks.SubdomainScanTask")
def SubdomainScanTask(url, active_scan_id, uid, subdomains=None):
    """子域名探测子任务"""
    try:
        scanner = SubdomainScan(url=url, active_scan_id=str(active_scan_id), uid=uid,
                                subdomains=subdomains)
        result = scanner.run()
        ErrorLog().Write("子域名探测完成 target=%s 发现=%s" % (url, result.get("found")))
        return result
    except Exception as e:
        ErrorLog().Write("子域名探测任务异常: %s" % e)
        return {"total": 0, "found": 0, "message": "子域名探测异常"}


@shared_task(name="Web.ActiveScan.ScanTasks.PassiveDetectTask")
def PassiveDetectTask(uid, proxy_id, url, request_headers, request_body,
                      request_method, status_code, body, response_headers):
    """被动扫描检测任务：对代理抓取到的流量执行插件检测"""
    try:
        from Web.ActiveScan.ExpressionEvaluator import ExpressionEvaluator, ResponseContext
        from Web.ActiveScan.PluginEngine import PluginEngine
        from ClassCongregation import VulnerabilityDetails

        evaluator = ExpressionEvaluator()
        engine = PluginEngine()
        plugins = engine.LoadAll()
        ctx = ResponseContext(status_code, body, response_headers or {}, url)

        hit_count = 0
        for plugin in plugins:
            for rule in plugin.rules:
                if evaluator.evaluate(rule.expression, ctx):
                    medusa = {
                        "name": plugin.name,
                        "number": "",
                        "author": plugin.Author(),
                        "create_date": "",
                        "algroup": plugin.name,
                        "rank": "高危",
                        "disclosure": "",
                        "details": "被动扫描发现\n目标: %s" % url,
                        "affects": plugin.name,
                        "desc_content": plugin.AffectedVersion(),
                        "suggest": "",
                        "version": plugin.AffectedVersion(),
                    }
                    _WritePassive(medusa, url, uid, proxy_id, status_code, body,
                                  response_headers, request_headers, request_body,
                                  request_method)
                    hit_count += 1
                    break
        return {"hit": hit_count}
    except Exception as e:
        ErrorLog().Write("被动检测任务异常: %s" % e)
        return {"hit": 0}


def _WritePassive(medusa, url, uid, proxy_id, status_code, body,
                  response_headers, request_headers, request_body, request_method):
    """构造响应对象并复用统一漏洞写入逻辑"""
    import requests
    response = requests.Response()
    response.status_code = status_code
    response._content = body if isinstance(body, bytes) else str(body or "").encode("utf-8")
    if response_headers:
        response.headers.update(response_headers)
    response.url = url
    response.request = requests.Request(
        method=request_method or "GET", url=url,
        headers=request_headers or {},
        data=request_body if isinstance(request_body, bytes) else None,
    ).prepare()

    VulnerabilityDetails(medusa, response, Url=url, Uid=uid,
                         ActiveScanId="PASSIVE-%s" % proxy_id).Write()
