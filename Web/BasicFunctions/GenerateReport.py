#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import json
import time
import uuid

from docxtpl import DocxTemplate, InlineImage
from docx.shared import Inches

from django.http import JsonResponse, FileResponse

from ClassCongregation import ErrorLog, GetPath
from Web.DatabaseHub import UserInfo, MedusaQuery, ReportGenerationList
from Web.Workbench.LogRelated import RequestLogRecord, UserOperationLogRecord


"""generate_word
{
    "token": "XXXXXX",
    "active_scan_id": "XXXXXXXX"
}
"""
def GenerateWord(request):  # 生成扫描报告
    RequestLogRecord(request, request_api="generate_word")
    if request.method == "POST":
        try:
            Token = json.loads(request.body)["token"]
            ActiveScanId = json.loads(request.body)["active_scan_id"]
            Uid = UserInfo().QueryUidWithToken(Token)  # 通过Token来查用户
            if Uid != None:  # 查到了UID
                UserOperationLogRecord(request, request_api="generate_word", uid=Uid)
                Result = MedusaQuery().QueryBySid(active_scan_id=ActiveScanId, uid=Uid)  # 查询扫描结果
                if Result != None:
                    ResultList = Result[0]
                    TargetUrl = Result[1]
                    # 为每条漏洞补充编号
                    for index, item in enumerate(ResultList):
                        item["vulnerability_number"] = index + 1
                    # 生成随机文件名
                    FileName = str(uuid.uuid4()) + ".docx"
                    DownloadFilePath = GetPath().DownloadFilePath()
                    if not os.path.exists(DownloadFilePath):  # 目录不存在则创建
                        os.makedirs(DownloadFilePath)
                    Doc = DocxTemplate(GetPath().TemplatePath() + "WordTemplate.docx")
                    Context = {
                        "home_picture": InlineImage(Doc, GetPath().ImageFilePath() + "admin.png", width=Inches(2)),
                        "target_url": TargetUrl,
                        "number_of_vulnerabilities_in_the_target_website": len(ResultList),
                        "vulnerability": ResultList,
                        "report_export_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                    }
                    Doc.render(Context)
                    Doc.save(DownloadFilePath + FileName)
                    ReportGenerationList().Write(uid=Uid, file_name=FileName, active_scan_id=ActiveScanId)  # 写入记录
                    return JsonResponse({'message': FileName, 'code': 200, })
                else:
                    return JsonResponse({'message': '扫描结果查询失败', 'code': 500, })
            else:
                return JsonResponse({'message': "小宝贝这是非法查询哦(๑•̀ㅂ•́)و✧", 'code': 403, })
        except Exception as e:
            ErrorLog().Write(e)
    else:
        return JsonResponse({'message': '请使用Post请求', 'code': 500, })


"""download_word
{
    "token": "XXXXXX",
    "file_name": "XXXXXXXX.docx"
}
"""
def DownloadWord(request):  # 下载扫描报告
    RequestLogRecord(request, request_api="download_word")
    if request.method == "POST":
        try:
            Token = json.loads(request.body)["token"]
            FileName = json.loads(request.body)["file_name"]
            Uid = UserInfo().QueryUidWithToken(Token)  # 通过Token来查用户
            if Uid != None:  # 查到了UID
                UserOperationLogRecord(request, request_api="download_word", uid=Uid)
                Result = ReportGenerationList().Query(uid=Uid, file_name=FileName)  # 校验该文件是否属于该用户
                if Result:
                    FilePath = GetPath().DownloadFilePath() + FileName
                    if os.path.exists(FilePath):
                        Response = FileResponse(open(FilePath, 'rb'), as_attachment=True, filename=FileName)
                        return Response
                    else:
                        return JsonResponse({'message': '文件不存在', 'code': 404, })
                else:
                    return JsonResponse({'message': "小宝贝这是非法查询哦(๑•̀ㅂ•́)و✧", 'code': 403, })
            else:
                return JsonResponse({'message': "小宝贝这是非法查询哦(๑•̀ㅂ•́)و✧", 'code': 403, })
        except Exception as e:
            ErrorLog().Write(e)
    else:
        return JsonResponse({'message': '请使用Post请求', 'code': 500, })
