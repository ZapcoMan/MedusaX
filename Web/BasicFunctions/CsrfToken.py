#!/usr/bin/env python
# -*- coding: utf-8 -*-
from django.http import JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie


@ensure_csrf_cookie
def GetCsrfToken(request):  # 下发 CSRF 令牌，同时通过响应写入 medusax_csrftoken Cookie
    """前端在发起任意 POST 请求前应先调用该接口获取令牌，
    接口会通过 Set-Cookie 下发令牌，并从响应体中返回同一份令牌，
    前端将令牌放入 X-CSRFToken 请求头即可通过校验。"""
    if request.method == "GET":
        token = request.META.get("CSRF_COOKIE", "")
        if not token:  # 极端情况下兜底再取一次，确保一定有值返回
            from django.middleware.csrf import get_token
            token = get_token(request)
        return JsonResponse({'message': token, 'code': 200, })
    return JsonResponse({'message': '请使用GET请求', 'code': 500, })


def CsrfFailure(request, reason=""):  # CSRF校验失败时返回JSON，便于前端识别后自动重试
    return JsonResponse({'message': 'CSRF验证失败，请刷新页面后重试', 'code': 403, }, status=403)
