#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""子域名探测模块

通过 DNS 枚举常见子域名字典发现目标域名下的资产。
为保证扫描器自身安全性，仅对解析成功的域名做记录，
并对泛解析（通配符解析）做过滤，避免产生大量误报。
"""
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from ClassCongregation import ErrorLog, SubdomainTable

# 常用子域名字典，覆盖常见业务与运维系统
DEFAULT_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
    "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "ns3", "test", "staging",
    "dev", "api", "admin", "blog", "shop", "forum", "news", "app", "m", "mobile",
    "wap", "cdn", "static", "img", "image", "js", "css", "upload", "download",
    "vpn", "remote", "git", "svn", "gitlab", "jenkins", "ci", "monitor", "zabbix",
    "nagios", "grafana", "kibana", "es", "elastic", "solr", "redis", "mysql",
    "db", "database", "oracle", "mssql", "postgres", "mongo", "backup", "bak",
    "old", "new", "demo", "preview", "docs", "doc", "wiki", "help", "support",
    "crm", "erp", "oa", "hr", "finance", "pay", "payment", "order", "user",
    "member", "account", "login", "sso", "auth", "cas", "id", "passport",
    "search", "s", "map", "gis", "video", "live", "media", "music", "file",
    "files", "disk", "cloud", "storage", "oss", "cos", "s3", "proxy", "gateway",
    "gw", "router", "firewall", "fw", "mail2", "mx", "mx1", "relay", "ns",
]

# 单次探测的最大并发数与DNS超时
MAX_WORKERS = 30
DNS_TIMEOUT = 3


class SubdomainScan:
    """子域名探测器"""

    def __init__(self, url: str, active_scan_id: str, uid: str, subdomains: list = None):
        self.url = url
        self.active_scan_id = active_scan_id
        self.uid = uid
        self.subdomains = subdomains or list(DEFAULT_SUBDOMAINS)
        self.found = []

    def ExtractDomain(self) -> str:
        """从目标URL中提取主域名

        优先使用 tldextract 精确提取注册域名，
        不可用时回退为按点号截取最后两级的简单处理。
        """
        host = self._ExtractHost()
        try:
            import tldextract
            extracted = tldextract.extract(host)
            if extracted.domain and extracted.suffix:
                return "%s.%s" % (extracted.domain, extracted.suffix)
        except Exception as e:
            ErrorLog().Write("tldextract 不可用，使用简易域名提取: %s" % e)

        parts = [p for p in host.split(".") if p]
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host

    def _ExtractHost(self) -> str:
        """提取目标主机名，去掉协议、端口与路径"""
        host = str(self.url or "").strip()
        if "://" in host:
            host = host.split("://", 1)[1]
        host = host.split("/", 1)[0]
        host = host.split(":", 1)[0]
        return host.strip().lower()

    def _IsWildcard(self, domain: str) -> bool:
        """检测目标是否开启泛解析

        若随机子域名也能解析成功，说明存在泛解析，后续需逐条比对IP去重。
        """
        random_host = "medusax-wildcard-check-%s.%s" % (int(time.time()), domain)
        try:
            socket.setdefaulttimeout(DNS_TIMEOUT)
            socket.gethostbyname(random_host)
            return True
        except Exception:
            return False
        finally:
            socket.setdefaulttimeout(None)

    def _Resolve(self, subdomain: str, domain: str):
        """解析单个子域名，成功返回 (完整域名, IP列表)"""
        full = "%s.%s" % (subdomain, domain)
        try:
            socket.setdefaulttimeout(DNS_TIMEOUT)
            result = socket.getaddrinfo(full, None)
            ips = sorted(set(item[4][0] for item in result))
            return full, ips
        except Exception:
            return None
        finally:
            socket.setdefaulttimeout(None)

    def run(self) -> dict:
        """执行子域名探测并落库"""
        domain = self.ExtractDomain()
        if not domain:
            return {"total": 0, "found": 0, "message": "域名解析失败"}

        has_wildcard = self._IsWildcard(domain)
        resolved = {}  # 完整域名 -> IP列表

        try:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
                futures = {pool.submit(self._Resolve, sub, domain): sub
                           for sub in self.subdomains}
                for future in as_completed(futures):
                    try:
                        item = future.result()
                    except Exception:
                        item = None
                    if item:
                        resolved[item[0]] = item[1]
        except Exception as e:
            ErrorLog().Write("子域名探测失败: %s" % e)

        # 泛解析场景下，剔除与其他子域名共享同一IP集合的条目以降低误报
        if has_wildcard and len(resolved) > 1:
            ip_counter = {}
            for ips in resolved.values():
                key = ",".join(ips)
                ip_counter[key] = ip_counter.get(key, 0) + 1
            majority_key = max(ip_counter, key=ip_counter.get)
            if ip_counter[majority_key] > 1:
                resolved = {k: v for k, v in resolved.items() if ",".join(v) != majority_key}

        for full_domain in sorted(resolved.keys()):
            try:
                SubdomainTable(full_domain, domain, Uid=self.uid,
                               ActiveScanId=self.active_scan_id).Write()
                self.found.append(full_domain)
            except Exception as e:
                ErrorLog().Write("子域名写入失败 %s: %s" % (full_domain, e))

        return {
            "total": len(self.subdomains),
            "found": len(self.found),
            "wildcard": has_wildcard,
            "message": "子域名探测完成",
        }
