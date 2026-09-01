#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""扫描插件引擎

负责加载 Plugins 目录下的 YAML 插件，解析为统一的内部结构并做合法性校验。
插件采用 nuclei 风格格式：

    name: poc-yaml-draytek-cve-2020-8515
    rules:
      - method: POST
        path: /cgi-bin/mainfunction.cgi
        headers:
          Content-Type: text/plain
        body: action=login
        expression: response.status == 200 && response.body.bcontains(b"uid")
    detail:
      author: xxx
      Affected Version: "xxx"
      links:
        - https://example.com

多规则(rules)的插件按顺序执行，最后一条规则的 expression 作为最终命中判定。
"""
import os
import yaml
from ClassCongregation import ErrorLog, GetPath

# 允许的HTTP方法白名单
ALLOWED_METHODS = {"GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH"}


class Plugin:  # 单条插件规则
    def __init__(self, method, path, headers, body, expression, follow_redirects=True):
        self.method = method
        self.path = path
        self.headers = headers or {}
        self.body = body
        self.expression = expression
        self.follow_redirects = follow_redirects


class PluginInfo:  # 一个完整的插件描述
    def __init__(self, file_name, name, rules, detail):
        self.file_name = file_name  # 插件文件名，用于去重与模块筛选
        self.name = name  # 插件名称
        self.rules = rules  # 规则列表，元素为 Plugin
        self.detail = detail or {}

    # 以下字段从 detail 中提取，供漏洞入库使用
    def Author(self) -> str:
        return str(self.detail.get("author", "") or "")

    def AffectedVersion(self) -> str:
        return str(self.detail.get("Affected Version", "") or "")

    def Links(self) -> str:
        links = self.detail.get("links", []) or []
        if isinstance(links, list):
            return "\n".join(str(i) for i in links)
        return str(links)


class PluginEngine:
    """插件加载与校验"""

    def __init__(self):
        self.plugins_path = GetPath().PluginsFilePath()
        self.errors = []  # 加载过程中的校验错误，供初始化接口回显

    def ListPluginFiles(self) -> list:
        """列出所有插件文件名"""
        result = []
        try:
            for root, dirs, files in os.walk(self.plugins_path):
                for file_name in files:
                    if file_name.lower().endswith((".yaml", ".yml")):
                        result.append(file_name)
        except Exception as e:
            ErrorLog().Write(e)
        return sorted(result)

    def Parse(self, file_name: str, content: str) -> PluginInfo or None:
        """解析单个插件内容，校验失败返回 None"""
        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as e:
            self.errors.append("%s: YAML解析失败(%s)" % (file_name, e))
            ErrorLog().Write("插件 %s YAML解析失败: %s" % (file_name, e))
            return None

        if not isinstance(data, dict):
            self.errors.append("%s: 插件内容不是合法的字典结构" % file_name)
            return None

        name = data.get("name")
        if not name:
            self.errors.append("%s: 缺少 name 字段" % file_name)
            return None

        raw_rules = data.get("rules")
        if not raw_rules or not isinstance(raw_rules, list):
            self.errors.append("%s: 缺少 rules 字段或格式非法" % file_name)
            return None

        rules = []
        for index, raw in enumerate(raw_rules):
            if not isinstance(raw, dict):
                self.errors.append("%s: 第%d条规则格式非法" % (file_name, index + 1))
                continue
            method = str(raw.get("method", "GET") or "GET").upper()
            if method not in ALLOWED_METHODS:
                self.errors.append("%s: 第%d条规则使用了不支持的方法 %s" % (file_name, index + 1, method))
                continue
            path = raw.get("path", "")
            if not path:
                self.errors.append("%s: 第%d条规则缺少 path" % (file_name, index + 1))
                continue
            expression = raw.get("expression", "")
            if not expression:
                self.errors.append("%s: 第%d条规则缺少 expression" % (file_name, index + 1))
                continue
            headers = raw.get("headers") or {}
            if not isinstance(headers, dict):
                headers = {}
            body = raw.get("body") or ""
            follow_redirects = raw.get("follow_redirects", True)
            rules.append(Plugin(method, path, headers, body, expression, follow_redirects))

        if not rules:
            self.errors.append("%s: 没有解析到任何有效规则" % file_name)
            return None

        return PluginInfo(file_name, str(name), rules, data.get("detail") or {})

    def LoadAll(self) -> list:
        """加载全部插件，返回 PluginInfo 列表"""
        plugins = []
        for file_name in self.ListPluginFiles():
            file_path = os.path.join(self.plugins_path, file_name)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
            except Exception as e:
                self.errors.append("%s: 读取失败(%s)" % (file_name, e))
                ErrorLog().Write(e)
                continue
            info = self.Parse(file_name, content)
            if info:
                plugins.append(info)
        return plugins

    def LoadByModule(self, module: str) -> list:
        """按模块筛选插件

        module 为 all 时返回全部；否则按插件名或文件名做包含匹配（忽略大小写）。
        """
        plugins = self.LoadAll()
        if not module or str(module).lower() == "all":
            return plugins
        keyword = str(module).lower()
        return [p for p in plugins if keyword in p.name.lower() or keyword in p.file_name.lower()]
