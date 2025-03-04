from django.shortcuts import redirect
from django.http import JsonResponse
from functools import wraps

def login_required(view_func):
    """
    登录验证装饰器，用于验证用户是否已登录
    如果未登录，则重定向到登录页面
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.session.get('user_id'):
            return redirect('index')
        return view_func(request, *args, **kwargs)
    return wrapper

def api_login_required(view_func):
    """
    API登录验证装饰器，用于验证用户是否已登录
    如果未登录，则返回JSON错误信息
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.session.get('user_id'):
            return JsonResponse({
                'code': 401,
                'msg': '用户未登录或会话已过期',
                'data': None
            })
        return view_func(request, *args, **kwargs)
    return wrapper
