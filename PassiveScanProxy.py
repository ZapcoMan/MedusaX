#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""被动扫描代理独立进程

沿用项目既有的独立服务模式（与 DNSServer.py / HTTPServer.py 一致），
以独立进程启动 mitmproxy 的 DumpMaster，加载被动扫描插件。

启动方式：
    python3 PassiveScanProxy.py

默认监听 0.0.0.0:8081，可通过环境变量覆盖：
    MEDUSA_PROXY_HOST / MEDUSA_PROXY_PORT
"""
import os
import asyncio
import sys

from ClassCongregation import ErrorLog

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8081


def BuildMaster():
    """构造 mitmproxy 的 DumpMaster 并挂载被动扫描插件"""
    from mitmproxy.tools.dump import DumpMaster
    from mitmproxy import options
    from Web.ActiveScan.ProxyScanAddon import PassiveScanAddon

    host = os.environ.get("MEDUSA_PROXY_HOST", DEFAULT_HOST)
    try:
        port = int(os.environ.get("MEDUSA_PROXY_PORT", DEFAULT_PORT))
    except (TypeError, ValueError):
        port = DEFAULT_PORT

    opts = options.Options(listen_host=host, listen_port=port)
    # 以透明上游模式运行，不解密无关流量，降低证书配置成本
    opts.flow_detail = 0  # 关闭控制台输出，避免刷屏
    opts.termlog_verbosity = "error"

    master = DumpMaster(opts, with_termlog=False, with_dumper=False)
    master.addons.add(PassiveScanAddon())
    return master, host, port


if __name__ == '__main__':
    master = None
    try:
        master, host, port = BuildMaster()
        ErrorLog().Write("被动扫描代理启动: %s:%s" % (host, port))
        asyncio.get_event_loop().run_until_complete(master.run())
    except KeyboardInterrupt:
        pass
    except ImportError as e:
        ErrorLog().Write("mitmproxy 未安装，被动扫描代理无法启动: %s" % e)
        sys.exit(0)  # 依赖缺失不阻断整体部署
    except Exception as e:
        ErrorLog().Write("被动扫描代理启动失败: %s" % e)
    finally:
        if master is not None:
            try:
                master.shutdown()
            except Exception:
                pass
