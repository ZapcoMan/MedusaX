#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""端口扫描模块

基于 python-nmap 调用系统 nmap 完成端口与服务识别。
若运行环境未安装 nmap 二进制或 python-nmap 不可用，
则自动降级为基于套接字连接的内置扫描，保证功能不中断。
"""
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from ClassCongregation import ErrorLog, PortDB, IpProcess

# 常用端口列表，作为默认扫描字典
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 139, 143, 161, 389, 443, 445, 465, 587, 873,
    993, 995, 1025, 1099, 1433, 1521, 2049, 2181, 2375, 3306, 3389, 5432, 5900,
    6379, 7001, 7002, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9200, 10000,
    11211, 27017, 50000,
]

# 端口范围上限，防止用户传入超大范围导致扫描失控
MAX_PORT = 65535
MAX_RANGE_SIZE = 2000


class PortScan:
    """端口扫描器"""

    def __init__(self, url: str, active_scan_id: str, uid: str, port_argument: str = ""):
        self.url = url
        self.active_scan_id = active_scan_id
        self.uid = uid
        self.port_argument = port_argument or ""  # 例如 "80,443" 或 "1-1000"
        self.results = []

    def ParsePorts(self) -> list:
        """解析用户传入的端口参数

        支持两种格式：
            1. 逗号分隔列表，例如 80,443,8080
            2. 范围格式，例如 1-1000
        留空或非法时使用默认端口字典。
        """
        argument = str(self.port_argument).strip()
        if not argument:
            return list(DEFAULT_PORTS)

        ports = []
        try:
            if "-" in argument:
                start_text, end_text = argument.split("-", 1)
                start = int(start_text.strip())
                end = int(end_text.strip())
                if start > end:
                    start, end = end, start
                start = max(1, start)
                end = min(MAX_PORT, end)
                if end - start + 1 > MAX_RANGE_SIZE:
                    end = start + MAX_RANGE_SIZE - 1
                ports = list(range(start, end + 1))
            else:
                for part in argument.split(","):
                    part = part.strip()
                    if not part:
                        continue
                    value = int(part)
                    if 1 <= value <= MAX_PORT:
                        ports.append(value)
        except (ValueError, TypeError) as e:
            ErrorLog().Write("端口参数解析失败，使用默认端口列表: %s" % e)
            return list(DEFAULT_PORTS)

        return ports or list(DEFAULT_PORTS)

    def ResolveTarget(self) -> tuple:
        """解析目标域名与IP，返回 (domain, ip)"""
        try:
            domain = IpProcess(self.url)
            ip = socket.gethostbyname(domain)
            return domain, ip
        except Exception as e:
            ErrorLog().Write("目标地址解析失败 %s: %s" % (self.url, e))
            return str(self.url), ""

    def ScanWithNmap(self, domain: str, ports: list) -> list:
        """使用nmap扫描，返回端口信息列表

        每个元素为 dict，包含 port/state/service/product/version 字段。
        """
        try:
            import nmap
        except ImportError:
            ErrorLog().Write("python-nmap 未安装，端口扫描降级为内置套接字扫描")
            return []

        scanner = nmap.PortScanner()
        port_text = ",".join(str(p) for p in ports)
        try:
            # -sV 识别服务版本，-T4 提升速度，--host-timeout 防止长时间阻塞
            scanner.scan(hosts=domain, ports=port_text,
                         arguments="-sV -T4 --host-timeout 300s")
        except Exception as e:
            ErrorLog().Write("nmap 执行失败，降级为内置套接字扫描: %s" % e)
            return []

        results = []
        try:
            for host in scanner.all_hosts():
                for protocol in scanner[host].all_protocols():
                    for port in sorted(scanner[host][protocol].keys()):
                        info = scanner[host][protocol][port]
                        results.append({
                            "port": str(port),
                            "state": str(info.get("state", "open")),
                            "service": str(info.get("name", "")),
                            "product": str(info.get("product", "")),
                            "version": str(info.get("version", "")),
                        })
        except Exception as e:
            ErrorLog().Write("nmap 结果解析失败: %s" % e)
        return results

    @staticmethod
    def _ProbeOne(host: str, port: int, timeout: float = 1.5) -> dict or None:
        """基于套接字探测单个端口是否开放"""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if sock.connect_ex((host, port)) == 0:
                return {"port": str(port), "state": "open", "service": "",
                        "product": "", "version": ""}
        except Exception:
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
        return None

    def ScanWithSocket(self, host: str, ports: list) -> list:
        """内置套接字并发探测，作为 nmap 不可用时的降级方案"""
        results = []
        try:
            with ThreadPoolExecutor(max_workers=50) as pool:
                futures = [pool.submit(self._ProbeOne, host, port) for port in ports]
                for future in as_completed(futures):
                    try:
                        item = future.result()
                    except Exception:
                        item = None
                    if item:
                        results.append(item)
        except Exception as e:
            ErrorLog().Write("套接字端口扫描失败: %s" % e)
        return sorted(results, key=lambda x: int(x["port"]))

    def run(self) -> dict:
        """执行端口扫描并落库，返回统计信息"""
        ports = self.ParsePorts()
        domain, ip = self.ResolveTarget()
        if not ip:
            return {"total": 0, "open": 0, "message": "目标地址解析失败"}

        results = self.ScanWithNmap(domain, ports)
        if not results:
            results = self.ScanWithSocket(ip, ports)

        creation_time = str(int(time.time()))
        for item in results:
            try:
                PortDB(uid=self.uid, active_scan_id=self.active_scan_id,
                       port=item.get("port"), ip=ip, domain=domain,
                       creation_time=creation_time, service=item.get("service", ""),
                       product=item.get("product", ""), version=item.get("version", ""),
                       state=item.get("state", "open")).Write()
            except Exception as e:
                ErrorLog().Write("端口信息写入失败: %s" % e)

        self.results = results
        return {"total": len(ports), "open": len(results), "message": "端口扫描完成"}
