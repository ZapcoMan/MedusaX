#!/usr/bin/env python
# -*- coding: utf-8 -*-
from Web.DatabaseHub import UserInfo,ProxyScanList,OriginalProxyData
from ClassCongregation import ErrorLog,Md5Encryption
from django.http import JsonResponse
import json
from Web.Workbench.LogRelated import RequestLogRecord,UserOperationLogRecord


"""create_proxy_scan_project
{
    "token": "0fs6lzGdC0QTun7wHC5VTNpvz9z6rXx6uOSxMhuGJgJnWMphU01wczYToY5mQ4vyzI0m5AyVPtYD368eNYOIRreAsgPfxwOvSxEKBLsVOcwCmVAtETuzTtr8z7iTmEfOASmtCM63YMOblM9EcZL8iJ6TsKtBXJHioJcvzNMqtgwEy6hLYQjbg7nTr3K5o1PDxxt9576UCXxJTQMADbJE2u1M0Q1tgEXFA3xG8uG38LEKPrh6hDzAaVdXPE",
    "proxy_project_name":"Soryu Asuka Langley",
    "proxy_username":"ascotbe",
    "proxy_password":"ascotbe",
    "end_time":"1610751014"
}
"""
def CreateProxyScanProject(request):#创建代理扫描项目
    RequestLogRecord(request, request_api="create_proxy_scan_project")
    if request.method == "POST":
        try:
            Token=json.loads(request.body)["token"]
            ProxyProjectName=json.loads(request.body)["proxy_project_name"]
            ProxyUsername=json.loads(request.body)["proxy_username"]
            ProxyPassword=json.loads(request.body)["proxy_password"]
            EndTime=json.loads(request.body)["end_time"]
            Uid = UserInfo().QueryUidWithToken(Token)  #通过Token来查用户
            if Uid != None:  # 查到了UID
                UserOperationLogRecord(request, request_api="create_proxy_scan_project", uid=Uid)
                #还需要查询项目名是否冲突
                QueryTheResultOfTheProxyProjectName=ProxyScanList().QueryProxyProjectName(uid=Uid, proxy_project_name=ProxyProjectName,proxy_username=ProxyUsername)#进行代理扫描项目查询，判断是否已经存在该项目
                if QueryTheResultOfTheProxyProjectName==False:
                    Md5ProxyPassword = Md5Encryption().Md5Result(ProxyPassword) # 对密码进行MD5加密
                    ProxyScanList().Write(uid=Uid,end_time=EndTime,proxy_project_name=ProxyProjectName,proxy_username=ProxyUsername,proxy_password=Md5ProxyPassword)#写入表中
                    return JsonResponse({'message': '小宝贝!创建成功了呢~', 'code': 200, })
                else:
                    return JsonResponse({'message': '代理扫描项目创建失败!', 'code': 503, })

            else:
                return JsonResponse({'message': "小宝贝这是非法查询哦(๑•̀ㅂ•́)و✧", 'code': 403, })
        except Exception as e:
            ErrorLog().Write(e)
    else:
        return JsonResponse({'message': '请使用Post请求', 'code': 500, })


#查询代理扫描项目
"""query_proxy_scan_project
{
    "token": "XXXXXX"
}
"""
def QueryProxyScanProject(request):#查询当前用户的代理扫描项目列表
    RequestLogRecord(request, request_api="query_proxy_scan_project")
    if request.method == "POST":
        try:
            Token=json.loads(request.body)["token"]
            Uid = UserInfo().QueryUidWithToken(Token)  #通过Token来查用户
            if Uid != None:  # 查到了UID
                UserOperationLogRecord(request, request_api="query_proxy_scan_project", uid=Uid)
                Result=ProxyScanList().Query(uid=Uid)
                if Result != None:
                    return JsonResponse({'message': Result, 'code': 200, })
                else:
                    return JsonResponse({'message': '查询失败', 'code': 500, })
            else:
                return JsonResponse({'message': "小宝贝这是非法查询哦(๑•̀ㅂ•́)و✧", 'code': 403, })
        except Exception as e:
            ErrorLog().Write(e)
    else:
        return JsonResponse({'message': '请使用Post请求', 'code': 500, })

"""update_proxy_scan_project_status
{
    "token": "XXXXXX",
    "proxy_id": "P1",
    "status": "1"
}
"""
def UpdateProxyScanProjectStatus(request):#启停代理扫描项目
    RequestLogRecord(request, request_api="update_proxy_scan_project_status")
    if request.method == "POST":
        try:
            Token=json.loads(request.body)["token"]
            ProxyId=json.loads(request.body)["proxy_id"]
            Status=json.loads(request.body)["status"]
            Uid = UserInfo().QueryUidWithToken(Token)  #通过Token来查用户
            if Uid != None:  # 查到了UID
                UserOperationLogRecord(request, request_api="update_proxy_scan_project_status", uid=Uid)
                Result=ProxyScanList().UpdateStatus(uid=Uid,proxy_id=ProxyId,status=Status)
                if Result:
                    return JsonResponse({'message': '状态更新成功', 'code': 200, })
                else:
                    return JsonResponse({'message': '状态更新失败', 'code': 500, })
            else:
                return JsonResponse({'message': "小宝贝这是非法查询哦(๑•̀ㅂ•́)و✧", 'code': 403, })
        except Exception as e:
            ErrorLog().Write(e)
    else:
        return JsonResponse({'message': '请使用Post请求', 'code': 500, })

"""delete_proxy_scan_project
{
    "token": "XXXXXX",
    "proxy_id": "P1"
}
"""
def DeleteProxyScanProject(request):#删除代理扫描项目
    RequestLogRecord(request, request_api="delete_proxy_scan_project")
    if request.method == "POST":
        try:
            Token=json.loads(request.body)["token"]
            ProxyId=json.loads(request.body)["proxy_id"]
            Uid = UserInfo().QueryUidWithToken(Token)  #通过Token来查用户
            if Uid != None:  # 查到了UID
                UserOperationLogRecord(request, request_api="delete_proxy_scan_project", uid=Uid)
                Result=ProxyScanList().Delete(uid=Uid,proxy_id=ProxyId)
                if Result:
                    return JsonResponse({'message': '删除成功', 'code': 200, })
                else:
                    return JsonResponse({'message': '删除失败', 'code': 500, })
            else:
                return JsonResponse({'message': "小宝贝这是非法查询哦(๑•̀ㅂ•́)و✧", 'code': 403, })
        except Exception as e:
            ErrorLog().Write(e)
    else:
        return JsonResponse({'message': '请使用Post请求', 'code': 500, })

"""query_proxy_scan_data
{
    "token": "XXXXXX",
    "proxy_id": "P1"
}
"""
def QueryProxyScanData(request):#查询代理抓取的原始流量数据
    RequestLogRecord(request, request_api="query_proxy_scan_data")
    if request.method == "POST":
        try:
            Token=json.loads(request.body)["token"]
            ProxyId=json.loads(request.body)["proxy_id"]
            Uid = UserInfo().QueryUidWithToken(Token)  #通过Token来查用户
            if Uid != None:  # 查到了UID
                UserOperationLogRecord(request, request_api="query_proxy_scan_data", uid=Uid)
                Result=OriginalProxyData().Query(uid=Uid,proxy_id=ProxyId)
                if Result != None:
                    return JsonResponse({'message': Result, 'code': 200, })
                else:
                    return JsonResponse({'message': '查询失败', 'code': 500, })
            else:
                return JsonResponse({'message': "小宝贝这是非法查询哦(๑•̀ㅂ•́)و✧", 'code': 403, })
        except Exception as e:
            ErrorLog().Write(e)
    else:
        return JsonResponse({'message': '请使用Post请求', 'code': 500, })
