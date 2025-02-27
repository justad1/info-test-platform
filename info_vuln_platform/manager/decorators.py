from django.shortcuts import redirect
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
