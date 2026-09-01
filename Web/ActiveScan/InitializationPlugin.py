#!/usr/bin/env python
# -*- coding: utf-8 -*-
from ClassCongregation import Plugins, GetPath, ErrorLog
from Web.ActiveScan.PluginEngine import PluginEngine
import os

def InitialVerification(TempFilePath):#验证是否初始化
    try:
        File=open(TempFilePath+"InitializationPlugin.lock", 'r+').read()
        if File.find("Super Invincible Cute Neiru Aonuma")!=-1:
            return True
        else:
            return False
    except:
        return False


def Run():
    """初始化插件库

    先沿用原有逻辑把插件文件名登记到 Plugins 表，
    再调用插件引擎做一次全量解析校验，把格式非法的插件写入错误日志，
    避免坏插件在扫描阶段才暴露问题。
    """
    TempFilePath = GetPath().TempFilePath()  # 获取TMP文件路径
    PluginsFilePath=GetPath().PluginsFilePath()#获取插件文件路径
    PluginsDB = Plugins()  # 初始化连接
    FileNameList=[]#文件名列表
    if not InitialVerification(TempFilePath):#如果不存在初始化
        PluginsDB.Initialization()#初始化清空数据库表
        for Data in os.walk(PluginsFilePath):
            for i in Data[2]:
                FileNameList.append((i,))
                if len(FileNameList) == 500:  # 500写入一次数据库
                    PluginsDB.Write(FileNameList)
                    FileNameList.clear()  # 写入后清空数据列表
        PluginsDB.Write(FileNameList)#函数循环结束后也写入一次数据库，防止不足500的数据没写入
        PluginsDB.con.close()#关闭数据库连接
        open(TempFilePath + "InitializationPlugin.lock", 'w+').write("Super Invincible Cute Neiru Aonuma")  # 初始化后写入初始化锁

    VerificationPlugin()  # 每次启动都做一次插件校验


def VerificationPlugin() -> dict:
    """校验全部插件，返回统计与错误信息"""
    engine = PluginEngine()
    plugins = engine.LoadAll()
    if engine.errors:
        for error in engine.errors:
            ErrorLog().Write("插件校验失败 -> %s" % error)
    return {"total": len(plugins), "errors": engine.errors}
