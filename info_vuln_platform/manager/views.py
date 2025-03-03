import json
import hashlib
from django.shortcuts import render, redirect
from django.views import View
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.core.paginator import Paginator

from .models import User, UserLog, FingerprintCategory, Fingerprint, Subdomain, PocCategory, Poc, BaseInfoQuery
from .decorators import login_required

# 导入子域名管理视图
from .views_subdomain import SubdomainView, SubdomainApiView

# 导入基础信息查询视图
from .views_baseinfo import BaseInfoView, BaseInfoApiView

# 创建密码哈希
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# 登录页面视图
class IndexView(View):
    def get(self, request):
        # 如果已经登录，重定向到后台首页
        if request.session.get('user_id'):
            return redirect('/manager/dashboard/')
        return render(request, 'managerlogin.html')
    
    def post(self, request):
        try:
            data = json.loads(request.body)
            username = data.get('username')
            password = data.get('password')
            
            # 验证用户名和密码
            try:
                user = User.objects.get(username=username)
                if user.password == hash_password(password) and user.is_active:
                    # 更新最后登录时间
                    user.last_login = timezone.now()
                    user.save()
                    
                    # 设置会话
                    request.session['user_id'] = user.id
                    request.session['username'] = user.username
                    request.session['is_admin'] = user.is_admin
                    
                    # 记录登录日志
                    UserLog.objects.create(
                        user=user,
                        action='用户登录',
                        ip=request.META.get('REMOTE_ADDR'),
                        details='用户登录成功'
                    )
                    
                    return JsonResponse({'status': 'success', 'message': '登录成功'})
                else:
                    return JsonResponse({'status': 'error', 'message': '密码错误'})
            except User.DoesNotExist:
                return JsonResponse({'status': 'error', 'message': '用户不存在'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})

# 后台首页视图
class DashboardView(View):
    def get(self, request):
        # 检查用户是否登录
        if not request.session.get('user_id'):
            return redirect('/manager/')
        
        context = {
            'username': request.session.get('username'),
            'is_admin': request.session.get('is_admin')
        }
        return render(request, 'dashboard.html', context)

# 用户列表页面视图
class UserListView(View):
    """用户列表视图"""
    
    @method_decorator(login_required)
    def get(self, request):
        # 检查是否为管理员
        if not request.session.get('is_admin'):
            return redirect('/manager/dashboard/')
        
        context = {}
        return render(request, 'user_list.html', context)

# 用户日志列表页面
class UserLogListView(View):
    """用户日志列表视图"""
    
    @method_decorator(login_required)
    def get(self, request):
        """渲染用户日志列表页面"""
        # 检查是否是管理员
        if not request.session.get('is_admin', False):
            return redirect('/manager/dashboard/')
        
        context = {}
        return render(request, 'user_log_list.html', context)

# 退出登录
class LogoutView(View):
    def get(self, request):
        # 记录退出日志
        if request.session.get('user_id'):
            try:
                user = User.objects.get(id=request.session.get('user_id'))
                UserLog.objects.create(
                    user=user,
                    action='用户退出',
                    ip=request.META.get('REMOTE_ADDR'),
                    details='用户退出登录'
                )
            except User.DoesNotExist:
                pass
        
        # 清除会话
        request.session.flush()
        # 重定向到登录页面，使用完整的URL路径
        return redirect('/manager/')

# 用户管理API
@method_decorator(csrf_exempt, name='dispatch')
class UserApiView(View):
    """用户管理API，提供用户的增删改查功能"""
    
    @method_decorator(login_required)
    def get(self, request, user_id=None):
        """获取用户列表或单个用户信息"""
        # 检查是否是管理员
        if not request.session.get('is_admin', False):
            return JsonResponse({
                'code': 403,
                'message': '权限不足，只有管理员可以访问用户管理功能'
            }, status=403)
        
        if user_id:
            # 获取单个用户信息
            try:
                user = User.objects.get(id=user_id)
                return JsonResponse({
                    'code': 200,
                    'message': '获取成功',
                    'data': {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email,
                        'is_admin': user.is_admin,
                        'is_active': user.is_active,
                        'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                        'last_login': user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else None
                    }
                })
            except User.DoesNotExist:
                return JsonResponse({
                    'code': 404,
                    'message': '用户不存在'
                }, status=404)
        else:
            # 获取用户列表
            page = int(request.GET.get('page', 1))
            limit = int(request.GET.get('limit', 10))
            
            start = (page - 1) * limit
            end = page * limit
            
            users = User.objects.all().order_by('-id')
            count = users.count()
            
            user_list = []
            for user in users[start:end]:
                user_list.append({
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'is_admin': user.is_admin,
                    'is_active': user.is_active,
                    'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                    'last_login': user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else None
                })
            
            return JsonResponse({
                'code': 200,
                'message': '获取成功',
                'count': count,
                'data': user_list
            })
    
    @method_decorator(login_required)
    def post(self, request):
        """添加用户"""
        # 检查是否是管理员
        if not request.session.get('is_admin', False):
            return JsonResponse({
                'code': 403,
                'message': '权限不足，只有管理员可以添加用户'
            }, status=403)
        
        try:
            data = json.loads(request.body)
            username = data.get('username')
            password = data.get('password')
            email = data.get('email', '')
            is_admin = data.get('is_admin', False)
            is_active = data.get('is_active', True)
            
            # 将字符串 "on" 转换为布尔值 True
            if is_admin == "on":
                is_admin = True
            if is_active == "on":
                is_active = True
            
            # 检查必填字段
            if not username or not password:
                return JsonResponse({
                    'code': 400,
                    'message': '用户名和密码不能为空'
                }, status=400)
            
            # 检查用户名是否已存在
            if User.objects.filter(username=username).exists():
                return JsonResponse({
                    'code': 400,
                    'message': f'用户名 {username} 已存在'
                }, status=400)
            
            # 创建用户
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            user = User.objects.create(
                username=username,
                password=password_hash,
                email=email,
                is_admin=is_admin,
                is_active=is_active
            )
            
            # 记录操作日志
            user_id = request.session.get('user_id')
            try:
                admin_user = User.objects.get(id=user_id)
                UserLog.objects.create(
                    user=admin_user,
                    action='添加用户',
                    ip=request.META.get('REMOTE_ADDR'),
                    details=f'添加用户 {username}，角色：{"管理员" if is_admin else "普通用户"}，状态：{"启用" if is_active else "禁用"}'
                )
            except User.DoesNotExist:
                # 如果找不到用户，就不记录日志
                pass
            
            return JsonResponse({
                'code': 200,
                'message': '添加成功',
                'data': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'is_admin': user.is_admin,
                    'is_active': user.is_active,
                    'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                    'last_login': None
                }
            })
        except json.JSONDecodeError:
            return JsonResponse({
                'code': 400,
                'message': '无效的JSON数据'
            }, status=400)
        except Exception as e:
            return JsonResponse({
                'code': 500,
                'message': f'服务器错误: {str(e)}'
            }, status=500)
    
    @method_decorator(login_required)
    def put(self, request, user_id):
        """更新用户信息"""
        # 检查是否是管理员
        if not request.session.get('is_admin', False):
            return JsonResponse({
                'code': 403,
                'message': '权限不足，只有管理员可以修改用户信息'
            }, status=403)
        
        try:
            # 检查用户是否存在
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return JsonResponse({
                    'code': 404,
                    'message': '用户不存在'
                }, status=404)
            
            data = json.loads(request.body)
            username = data.get('username')
            password = data.get('password')
            email = data.get('email', '')
            is_admin = data.get('is_admin', False)
            is_active = data.get('is_active', True)
            
            # 将字符串 "on" 转换为布尔值 True
            if is_admin == "on":
                is_admin = True
            if is_active == "on":
                is_active = True
            
            # 检查用户名是否已存在（排除当前用户）
            if username and username != user.username and User.objects.filter(username=username).exists():
                return JsonResponse({
                    'code': 400,
                    'message': f'用户名 {username} 已存在'
                }, status=400)
            
            # 更新用户信息
            if username:
                user.username = username
            if password:
                user.password = hashlib.sha256(password.encode()).hexdigest()
            if email is not None:
                user.email = email
            user.is_admin = is_admin
            user.is_active = is_active
            user.save()
            
            return JsonResponse({
                'code': 200,
                'message': '更新成功',
                'data': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'is_admin': user.is_admin,
                    'is_active': user.is_active,
                    'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                    'last_login': user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else None
                }
            })
        except json.JSONDecodeError:
            return JsonResponse({
                'code': 400,
                'message': '无效的JSON数据'
            }, status=400)
        except Exception as e:
            return JsonResponse({
                'code': 500,
                'message': f'服务器错误: {str(e)}'
            }, status=500)
    
    @method_decorator(login_required)
    def delete(self, request, user_id):
        """删除用户"""
        # 检查是否是管理员
        if not request.session.get('is_admin', False):
            return JsonResponse({
                'code': 403,
                'message': '权限不足，只有管理员可以删除用户'
            }, status=403)
        
        try:
            # 检查用户是否存在
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return JsonResponse({
                    'code': 404,
                    'message': '用户不存在'
                }, status=404)
            
            # 不能删除自己
            if user.id == request.session.get('user_id'):
                return JsonResponse({
                    'code': 400,
                    'message': '不能删除自己'
                }, status=400)
            
            # 删除用户
            username = user.username
            user.delete()
            
            # 记录操作日志
            try:
                admin_user = User.objects.get(id=request.session.get('user_id'))
                UserLog.objects.create(
                    user=admin_user,
                    action='删除用户',
                    ip=request.META.get('REMOTE_ADDR'),
                    details=f'删除用户 {username}'
                )
            except User.DoesNotExist:
                pass
            
            return JsonResponse({
                'code': 200,
                'message': '删除成功'
            })
        except Exception as e:
            return JsonResponse({
                'code': 500,
                'message': f'服务器错误: {str(e)}'
            }, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class UserBatchDeleteView(View):
    """批量删除用户"""
    
    @method_decorator(login_required)
    def post(self, request):
        # 检查是否是管理员
        if not request.session.get('is_admin', False):
            return JsonResponse({
                'code': 403,
                'message': '权限不足，只有管理员可以删除用户'
            }, status=403)
        
        try:
            data = json.loads(request.body)
            ids = data.get('ids', [])
            
            if not ids:
                return JsonResponse({
                    'code': 400,
                    'message': '未选择要删除的用户'
                }, status=400)
            
            # 批量删除用户
            deleted_users = []
            for user_id in ids:
                try:
                    user = User.objects.get(id=user_id)
                    # 不能删除自己
                    if user.id == request.session.get('user_id'):
                        continue
                    username = user.username
                    user.delete()
                    deleted_users.append(username)
                except User.DoesNotExist:
                    continue
            
            # 记录操作日志
            if deleted_users:
                try:
                    admin_user = User.objects.get(id=request.session.get('user_id'))
                    UserLog.objects.create(
                        user=admin_user,
                        action='批量删除用户',
                        ip=request.META.get('REMOTE_ADDR'),
                        details=f'批量删除用户：{", ".join(deleted_users)}'
                    )
                except User.DoesNotExist:
                    pass
            
            return JsonResponse({
                'code': 200,
                'message': '批量删除成功'
            })
        except json.JSONDecodeError:
            return JsonResponse({
                'code': 400,
                'message': '无效的JSON数据'
            }, status=400)
        except Exception as e:
            return JsonResponse({
                'code': 500,
                'message': f'服务器错误: {str(e)}'
            }, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class UserToggleAdminView(View):
    """切换用户管理员状态"""
    
    @method_decorator(login_required)
    def post(self, request, user_id):
        # 检查是否是管理员
        if not request.session.get('is_admin', False):
            return JsonResponse({
                'code': 403,
                'message': '权限不足，只有管理员可以修改用户权限'
            }, status=403)
        
        try:
            # 检查用户是否存在
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return JsonResponse({
                    'code': 404,
                    'message': '用户不存在'
                }, status=404)
            
            data = json.loads(request.body)
            is_admin = data.get('is_admin', False)
            
            # 将字符串 "on" 转换为布尔值 True
            if is_admin == "on":
                is_admin = True
            
            # 不能修改自己的管理员状态
            if user.id == request.session.get('user_id'):
                return JsonResponse({
                    'code': 400,
                    'message': '不能修改自己的管理员状态'
                }, status=400)
            
            # 更新用户管理员状态
            user.is_admin = is_admin
            user.save()
            
            # 记录操作日志
            try:
                admin_user = User.objects.get(id=request.session.get('user_id'))
                UserLog.objects.create(
                    user=admin_user,
                    action='修改用户角色',
                    ip=request.META.get('REMOTE_ADDR'),
                    details=f'将用户 {user.username} 的角色修改为 {"管理员" if is_admin else "普通用户"}'
                )
            except User.DoesNotExist:
                pass
            
            return JsonResponse({
                'code': 200,
                'message': '修改成功',
                'data': {
                    'id': user.id,
                    'is_admin': user.is_admin
                }
            })
        except json.JSONDecodeError:
            return JsonResponse({
                'code': 400,
                'message': '无效的JSON数据'
            }, status=400)
        except Exception as e:
            return JsonResponse({
                'code': 500,
                'message': f'服务器错误: {str(e)}'
            }, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class UserToggleActiveView(View):
    """切换用户激活状态"""
    
    @method_decorator(login_required)
    def post(self, request, user_id):
        # 检查是否是管理员
        if not request.session.get('is_admin', False):
            return JsonResponse({
                'code': 403,
                'message': '权限不足，只有管理员可以修改用户状态'
            }, status=403)
        
        try:
            # 检查用户是否存在
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return JsonResponse({
                    'code': 404,
                    'message': '用户不存在'
                }, status=404)
            
            data = json.loads(request.body)
            is_active = data.get('is_active', True)
            
            # 将字符串 "on" 转换为布尔值 True
            if is_active == "on":
                is_active = True
            
            # 不能修改自己的激活状态
            if user.id == request.session.get('user_id'):
                return JsonResponse({
                    'code': 400,
                    'message': '不能修改自己的激活状态'
                }, status=400)
            
            # 更新用户激活状态
            user.is_active = is_active
            user.save()
            
            return JsonResponse({
                'code': 200,
                'message': '修改成功',
                'data': {
                    'id': user.id,
                    'is_active': user.is_active
                }
            })
        except json.JSONDecodeError:
            return JsonResponse({
                'code': 400,
                'message': '无效的JSON数据'
            }, status=400)
        except Exception as e:
            return JsonResponse({
                'code': 500,
                'message': f'服务器错误: {str(e)}'
            }, status=500)

# 用户日志API
@method_decorator(csrf_exempt, name='dispatch')
class UserLogApiView(View):
    """用户日志API，提供用户日志的查询功能"""
    
    @method_decorator(login_required)
    def get(self, request):
        """获取用户日志列表"""
        # 检查是否是管理员
        if not request.session.get('is_admin', False):
            return JsonResponse({
                'code': 403,
                'message': '权限不足，只有管理员可以访问用户日志'
            }, status=403)
        
        # 获取查询参数
        page = int(request.GET.get('page', 1))
        limit = int(request.GET.get('limit', 10))
        username = request.GET.get('username', '')
        action = request.GET.get('action', '')
        start_date = request.GET.get('start_date', '')
        end_date = request.GET.get('end_date', '')
        
        # 构建查询条件
        query = {}
        if username:
            users = User.objects.filter(username__icontains=username)
            query['user__in'] = users
        if action:
            query['action__icontains'] = action
        if start_date:
            query['created_at__gte'] = start_date
        if end_date:
            query['created_at__lte'] = end_date
        
        # 查询日志
        logs = UserLog.objects.filter(**query).order_by('-created_at')
        count = logs.count()
        
        # 分页
        paginator = Paginator(logs, limit)
        logs_page = paginator.get_page(page)
        
        # 构建返回数据
        log_list = []
        for log in logs_page:
            log_list.append({
                'id': log.id,
                'username': log.user.username if log.user else '未知用户',
                'action': log.action,
                'ip': log.ip,
                'details': log.details,
                'created_at': log.created_at.strftime('%Y-%m-%d %H:%M:%S')
            })
        
        return JsonResponse({
            'code': 200,
            'message': '获取成功',
            'count': count,
            'data': log_list
        })

# 个人信息页面
class ProfileView(View):
    """个人信息页面，显示当前用户的信息"""
    
    @method_decorator(login_required)
    def get(self, request):
        """渲染个人信息页面"""
        # 获取当前用户
        user_id = request.session.get('user_id')
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return redirect('/manager/')
        
        context = {
            'user': user,
            'username': user.username,
            'is_admin': user.is_admin
        }
        return render(request, 'profile.html', context)

# 个人信息API
@method_decorator(csrf_exempt, name='dispatch')
class ProfileApiView(View):
    """个人信息API，提供个人信息的更新功能"""
    
    @method_decorator(login_required)
    def post(self, request):
        """更新个人信息"""
        try:
            # 获取当前用户
            user_id = request.session.get('user_id')
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return JsonResponse({
                    'code': 404,
                    'message': '用户不存在'
                }, status=404)
            
            data = json.loads(request.body)
            email = data.get('email', '')
            
            # 更新用户信息
            user.email = email
            user.save()
            
            # 记录操作日志
            UserLog.objects.create(
                user=user,
                action='更新个人信息',
                ip=request.META.get('REMOTE_ADDR'),
                details='更新了个人邮箱信息'
            )
            
            return JsonResponse({
                'code': 200,
                'message': '更新成功'
            })
        except json.JSONDecodeError:
            return JsonResponse({
                'code': 400,
                'message': '无效的JSON数据'
            }, status=400)
        except Exception as e:
            return JsonResponse({
                'code': 500,
                'message': f'服务器错误: {str(e)}'
            }, status=500)

# 修改密码页面
class ChangePasswordView(View):
    """修改密码页面，允许用户修改自己的密码"""
    
    @method_decorator(login_required)
    def get(self, request):
        """渲染修改密码页面"""
        # 获取当前用户
        user_id = request.session.get('user_id')
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return redirect('/manager/')
        
        context = {
            'username': user.username,
            'is_admin': user.is_admin
        }
        return render(request, 'change_password.html', context)

# 修改密码API
@method_decorator(csrf_exempt, name='dispatch')
class ChangePasswordApiView(View):
    """修改密码API，提供密码修改功能"""
    
    @method_decorator(login_required)
    @method_decorator(csrf_exempt)
    def post(self, request):
        try:
            data = json.loads(request.body)
            old_password = data.get('old_password')
            new_password = data.get('new_password')
            confirm_password = data.get('confirm_password')
            
            # 验证新密码和确认密码是否一致
            if new_password != confirm_password:
                return JsonResponse({'code': 400, 'msg': '新密码和确认密码不一致'})
            
            # 验证旧密码是否正确
            user = User.objects.get(id=request.session.get('user_id'))
            if user.password != hash_password(old_password):
                return JsonResponse({'code': 400, 'msg': '旧密码不正确'})
            
            # 更新密码
            user.password = hash_password(new_password)
            user.save()
            
            # 记录日志
            UserLog.objects.create(
                user=user,
                action='修改密码',
                ip=request.META.get('REMOTE_ADDR'),
                details='用户修改了密码'
            )
            
            return JsonResponse({'code': 200, 'msg': '密码修改成功'})
        except Exception as e:
            return JsonResponse({'code': 500, 'msg': f'服务器错误: {str(e)}'})

# 指纹分类页面视图
class FingerprintCategoryView(View):
    """指纹分类页面视图"""
    
    @method_decorator(login_required)
    def get(self, request):
        return render(request, 'fingerprint_category.html')

# 指纹管理页面视图
class FingerprintManagementView(View):
    """指纹管理页面视图"""
    
    @method_decorator(login_required)
    def get(self, request):
        return render(request, 'fingerprint_management.html')

# 指纹分类API
class FingerprintCategoryApiView(View):
    """指纹分类API，提供指纹分类的增删改查功能"""
    
    @method_decorator(login_required)
    def get(self, request, category_id=None):
        try:
            if category_id:
                # 获取单个分类信息
                category = FingerprintCategory.objects.get(id=category_id)
                data = {
                    'id': category.id,
                    'name': category.name,
                    'description': category.description,
                    'create_time': category.create_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'update_time': category.update_time.strftime('%Y-%m-%d %H:%M:%S')
                }
                return JsonResponse({'code': 200, 'msg': '获取成功', 'data': data})
            else:
                # 获取分类列表
                page = int(request.GET.get('page', 1))
                limit = int(request.GET.get('limit', 10))
                
                categories = FingerprintCategory.objects.all()
                
                # 分页
                paginator = Paginator(categories, limit)
                page_obj = paginator.get_page(page)
                
                data = []
                for category in page_obj:
                    data.append({
                        'id': category.id,
                        'name': category.name,
                        'description': category.description,
                        'create_time': category.create_time.strftime('%Y-%m-%d %H:%M:%S'),
                        'update_time': category.update_time.strftime('%Y-%m-%d %H:%M:%S')
                    })
                
                return JsonResponse({
                    'code': 200,
                    'msg': '获取成功',
                    'count': paginator.count,
                    'data': data
                })
        except FingerprintCategory.DoesNotExist:
            return JsonResponse({'code': 404, 'msg': '分类不存在'})
        except Exception as e:
            return JsonResponse({'code': 500, 'msg': f'服务器错误: {str(e)}'})
    
    @method_decorator(login_required)
    @method_decorator(csrf_exempt)
    def post(self, request):
        try:
            data = json.loads(request.body) if request.body else request.POST
            name = data.get('name')
            description = data.get('description', '')
            
            # 验证分类名称是否已存在
            if FingerprintCategory.objects.filter(name=name).exists():
                return JsonResponse({'code': 400, 'msg': '分类名称已存在'})
            
            # 创建分类
            category = FingerprintCategory.objects.create(
                name=name,
                description=description
            )
            
            # 记录日志
            UserLog.objects.create(
                user=User.objects.get(id=request.session.get('user_id')),
                action='创建指纹分类',
                ip=request.META.get('REMOTE_ADDR'),
                details=f'创建了指纹分类: {name}'
            )
            
            return JsonResponse({'code': 200, 'msg': '创建成功', 'data': {'id': category.id}})
        except Exception as e:
            return JsonResponse({'code': 500, 'msg': f'服务器错误: {str(e)}'})
    
    @method_decorator(login_required)
    @method_decorator(csrf_exempt)
    def put(self, request, category_id):
        try:
            data = json.loads(request.body) if request.body else request.POST
            name = data.get('name')
            description = data.get('description', '')
            
            # 验证分类是否存在
            try:
                category = FingerprintCategory.objects.get(id=category_id)
            except FingerprintCategory.DoesNotExist:
                return JsonResponse({'code': 404, 'msg': '分类不存在'})
            
            # 验证分类名称是否已存在（排除当前分类）
            if FingerprintCategory.objects.filter(name=name).exclude(id=category_id).exists():
                return JsonResponse({'code': 400, 'msg': '分类名称已存在'})
            
            # 更新分类
            category.name = name
            category.description = description
            category.save()
            
            # 记录日志
            UserLog.objects.create(
                user=User.objects.get(id=request.session.get('user_id')),
                action='更新指纹分类',
                ip=request.META.get('REMOTE_ADDR'),
                details=f'更新了指纹分类: {name}'
            )
            
            return JsonResponse({'code': 200, 'msg': '更新成功'})
        except Exception as e:
            return JsonResponse({'code': 500, 'msg': f'服务器错误: {str(e)}'})
    
    @method_decorator(login_required)
    def delete(self, request, category_id):
        try:
            # 验证分类是否存在
            try:
                category = FingerprintCategory.objects.get(id=category_id)
            except FingerprintCategory.DoesNotExist:
                return JsonResponse({'code': 404, 'msg': '分类不存在'})
            
            # 检查分类下是否有指纹
            if Fingerprint.objects.filter(category=category).exists():
                return JsonResponse({'code': 400, 'msg': '该分类下存在指纹，无法删除'})
            
            # 记录分类名称，用于日志记录
            category_name = category.name
            
            # 删除分类
            category.delete()
            
            # 记录日志
            UserLog.objects.create(
                user=User.objects.get(id=request.session.get('user_id')),
                action='删除指纹分类',
                ip=request.META.get('REMOTE_ADDR'),
                details=f'删除了指纹分类: {category_name}'
            )
            
            return JsonResponse({'code': 200, 'msg': '删除成功'})
        except Exception as e:
            return JsonResponse({'code': 500, 'msg': f'服务器错误: {str(e)}'})

# 指纹API
class FingerprintApiView(View):
    """指纹API，提供指纹的增删改查功能"""
    
    @method_decorator(login_required)
    def get(self, request, fingerprint_id=None):
        try:
            if fingerprint_id:
                # 获取单个指纹信息
                fingerprint = Fingerprint.objects.get(id=fingerprint_id)
                data = {
                    'id': fingerprint.id,
                    'name': fingerprint.name,
                    'category_id': fingerprint.category.id,
                    'category_name': fingerprint.category.name,
                    'rule': fingerprint.rule,
                    'position': fingerprint.position,
                    'description': fingerprint.description,
                    'create_time': fingerprint.create_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'update_time': fingerprint.update_time.strftime('%Y-%m-%d %H:%M:%S')
                }
                return JsonResponse({'code': 200, 'msg': '获取成功', 'data': data})
            else:
                # 获取指纹列表
                page = int(request.GET.get('page', 1))
                limit = int(request.GET.get('limit', 10))
                name = request.GET.get('name', '')
                category_id = request.GET.get('category_id', '')
                
                fingerprints = Fingerprint.objects.all()
                
                # 按名称筛选
                if name:
                    fingerprints = fingerprints.filter(name__icontains=name)
                
                # 按分类筛选
                if category_id:
                    fingerprints = fingerprints.filter(category_id=category_id)
                
                # 分页
                paginator = Paginator(fingerprints, limit)
                page_obj = paginator.get_page(page)
                
                data = []
                for fingerprint in page_obj:
                    data.append({
                        'id': fingerprint.id,
                        'name': fingerprint.name,
                        'category_id': fingerprint.category.id,
                        'category_name': fingerprint.category.name,
                        'rule': fingerprint.rule,
                        'position': fingerprint.position,
                        'description': fingerprint.description,
                        'create_time': fingerprint.create_time.strftime('%Y-%m-%d %H:%M:%S'),
                        'update_time': fingerprint.update_time.strftime('%Y-%m-%d %H:%M:%S')
                    })
                
                return JsonResponse({
                    'code': 200,
                    'msg': '获取成功',
                    'count': paginator.count,
                    'data': data
                })
        except Fingerprint.DoesNotExist:
            return JsonResponse({'code': 404, 'msg': '指纹不存在'})
        except Exception as e:
            return JsonResponse({'code': 500, 'msg': f'服务器错误: {str(e)}'})
    
    @method_decorator(login_required)
    @method_decorator(csrf_exempt)
    def post(self, request):
        try:
            data = json.loads(request.body) if request.body else request.POST
            name = data.get('name')
            category_id = data.get('category_id')
            rule = data.get('rule')
            position = data.get('position')
            description = data.get('description', '')
            
            # 验证分类是否存在
            try:
                category = FingerprintCategory.objects.get(id=category_id)
            except FingerprintCategory.DoesNotExist:
                return JsonResponse({'code': 404, 'msg': '分类不存在'})
            
            # 创建指纹
            fingerprint = Fingerprint.objects.create(
                name=name,
                category=category,
                rule=rule,
                position=position,
                description=description
            )
            
            # 记录日志
            UserLog.objects.create(
                user=User.objects.get(id=request.session.get('user_id')),
                action='创建指纹',
                ip=request.META.get('REMOTE_ADDR'),
                details=f'创建了指纹: {name}'
            )
            
            return JsonResponse({'code': 200, 'msg': '创建成功', 'data': {'id': fingerprint.id}})
        except Exception as e:
            return JsonResponse({'code': 500, 'msg': f'服务器错误: {str(e)}'})
    
    @method_decorator(login_required)
    @method_decorator(csrf_exempt)
    def put(self, request, fingerprint_id):
        try:
            data = json.loads(request.body) if request.body else request.POST
            name = data.get('name')
            category_id = data.get('category_id')
            rule = data.get('rule')
            position = data.get('position')
            description = data.get('description', '')
            
            # 验证指纹是否存在
            try:
                fingerprint = Fingerprint.objects.get(id=fingerprint_id)
            except Fingerprint.DoesNotExist:
                return JsonResponse({'code': 404, 'msg': '指纹不存在'})
            
            # 验证分类是否存在
            try:
                category = FingerprintCategory.objects.get(id=category_id)
            except FingerprintCategory.DoesNotExist:
                return JsonResponse({'code': 404, 'msg': '分类不存在'})
            
            # 更新指纹
            fingerprint.name = name
            fingerprint.category = category
            fingerprint.rule = rule
            fingerprint.position = position
            fingerprint.description = description
            fingerprint.save()
            
            # 记录日志
            UserLog.objects.create(
                user=User.objects.get(id=request.session.get('user_id')),
                action='更新指纹',
                ip=request.META.get('REMOTE_ADDR'),
                details=f'更新了指纹: {name}'
            )
            
            return JsonResponse({'code': 200, 'msg': '更新成功'})
        except Exception as e:
            return JsonResponse({'code': 500, 'msg': f'服务器错误: {str(e)}'})
    
    @method_decorator(login_required)
    def delete(self, request, fingerprint_id):
        try:
            # 验证指纹是否存在
            try:
                fingerprint = Fingerprint.objects.get(id=fingerprint_id)
            except Fingerprint.DoesNotExist:
                return JsonResponse({'code': 404, 'msg': '指纹不存在'})
            
            # 记录指纹名称，用于日志记录
            fingerprint_name = fingerprint.name
            
            # 删除指纹
            fingerprint.delete()
            
            # 记录日志
            UserLog.objects.create(
                user=User.objects.get(id=request.session.get('user_id')),
                action='删除指纹',
                ip=request.META.get('REMOTE_ADDR'),
                details=f'删除了指纹: {fingerprint_name}'
            )
            
            return JsonResponse({'code': 200, 'msg': '删除成功'})
        except Exception as e:
            return JsonResponse({'code': 500, 'msg': f'服务器错误: {str(e)}'})

# 子域名管理视图
class SubdomainView(View):
    """子域名管理页面"""
    def get(self, request):
        return render(request, 'subdomain.html')

# 子域名API
class SubdomainApiView(View):
    """子域名API"""
    def get(self, request, subdomain_id=None):
        """获取子域名列表或单个子域名信息"""
        try:
            # 如果提供了子域名ID，返回单个子域名信息
            if subdomain_id:
                try:
                    subdomain = Subdomain.objects.get(id=subdomain_id)
                    return JsonResponse({
                        'code': 200,
                        'msg': '获取子域名信息成功',
                        'data': {
                            'id': subdomain.id,
                            'domain': subdomain.domain,
                            'subdomain': subdomain.subdomain,
                            'ip': subdomain.ip,
                            'status': subdomain.status,
                            'title': subdomain.title,
                            'server': subdomain.server,
                            'create_time': subdomain.create_time.strftime('%Y-%m-%d %H:%M:%S'),
                            'update_time': subdomain.update_time.strftime('%Y-%m-%d %H:%M:%S')
                        }
                    })
                except Subdomain.DoesNotExist:
                    return JsonResponse({'code': 404, 'msg': '子域名不存在'})
            
            # 获取查询参数
            page = int(request.GET.get('page', 1))
            limit = int(request.GET.get('limit', 10))
            domain = request.GET.get('domain', '')
            subdomain = request.GET.get('subdomain', '')
            
            # 查询子域名
            query = Subdomain.objects.all()
            
            # 应用过滤条件
            if domain:
                query = query.filter(domain__icontains=domain)
            if subdomain:
                query = query.filter(subdomain__icontains=subdomain)
            
            # 计算总数
            count = query.count()
            
            # 分页
            paginator = Paginator(query, limit)
            page_obj = paginator.get_page(page)
            
            # 准备响应数据
            data = []
            for item in page_obj:
                data.append({
                    'id': item.id,
                    'domain': item.domain,
                    'subdomain': item.subdomain,
                    'ip': item.ip,
                    'status': item.status,
                    'title': item.title,
                    'server': item.server,
                    'create_time': item.create_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'update_time': item.update_time.strftime('%Y-%m-%d %H:%M:%S')
                })
            
            # 返回成功响应
            return JsonResponse({
                'code': 200,
                'msg': '获取子域名列表成功',
                'count': count,
                'data': data
            })
        except Exception as e:
            # 返回错误响应
            return JsonResponse({
                'code': 500,
                'msg': f'获取子域名列表失败：{str(e)}',
                'count': 0,
                'data': []
            })
    
    def post(self, request):
        """添加子域名"""
        try:
            # 解析请求数据
            data = json.loads(request.body)
            domain = data.get('domain', '').strip()
            subdomain = data.get('subdomain', '').strip()
            ip = data.get('ip', '').strip()
            status = data.get('status')
            title = data.get('title', '').strip()
            server = data.get('server', '').strip()
            
            # 验证必填字段
            if not domain:
                return JsonResponse({'code': 400, 'msg': '主域名不能为空'})
            if not subdomain:
                return JsonResponse({'code': 400, 'msg': '子域名不能为空'})
            
            # 检查是否已存在
            if Subdomain.objects.filter(domain=domain, subdomain=subdomain).exists():
                return JsonResponse({'code': 400, 'msg': '该子域名已存在'})
            
            # 创建子域名
            subdomain_obj = Subdomain.objects.create(
                domain=domain,
                subdomain=subdomain,
                ip=ip,
                status=status,
                title=title,
                server=server
            )
            
            # 记录操作日志
            try:
                user_id = request.session.get('user_id')
                if user_id:
                    user = User.objects.get(id=user_id)
                    UserLog.objects.create(
                        user=user,
                        action='添加子域名',
                        ip=request.META.get('REMOTE_ADDR'),
                        details=f'添加子域名：{subdomain}.{domain}'
                    )
            except Exception as log_error:
                print(f"记录日志错误: {str(log_error)}")
            
            # 返回成功响应
            return JsonResponse({
                'code': 200,
                'msg': '添加子域名成功',
                'data': {
                    'id': subdomain_obj.id,
                    'domain': subdomain_obj.domain,
                    'subdomain': subdomain_obj.subdomain,
                    'ip': subdomain_obj.ip,
                    'status': subdomain_obj.status,
                    'title': subdomain_obj.title,
                    'server': subdomain_obj.server,
                    'create_time': subdomain_obj.create_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'update_time': subdomain_obj.update_time.strftime('%Y-%m-%d %H:%M:%S')
                }
            })
        except Exception as e:
            # 返回错误响应
            return JsonResponse({'code': 500, 'msg': f'添加子域名失败：{str(e)}'})
    
    def put(self, request, subdomain_id=None):
        """更新子域名"""
        try:
            # 检查子域名ID
            if not subdomain_id:
                return JsonResponse({'code': 400, 'msg': '缺少子域名ID'})
            
            # 检查子域名是否存在
            try:
                subdomain_obj = Subdomain.objects.get(id=subdomain_id)
            except Subdomain.DoesNotExist:
                return JsonResponse({'code': 404, 'msg': '子域名不存在'})
            
            # 解析请求数据
            data = json.loads(request.body)
            domain = data.get('domain', '').strip()
            subdomain = data.get('subdomain', '').strip()
            ip = data.get('ip', '').strip()
            status = data.get('status')
            title = data.get('title', '').strip()
            server = data.get('server', '').strip()
            
            # 验证必填字段
            if not domain:
                return JsonResponse({'code': 400, 'msg': '主域名不能为空'})
            if not subdomain:
                return JsonResponse({'code': 400, 'msg': '子域名不能为空'})
            
            # 检查是否已存在（排除当前记录）
            if Subdomain.objects.filter(domain=domain, subdomain=subdomain).exclude(id=subdomain_id).exists():
                return JsonResponse({'code': 400, 'msg': '该子域名已存在'})
            
            # 更新子域名
            subdomain_obj.domain = domain
            subdomain_obj.subdomain = subdomain
            subdomain_obj.ip = ip
            subdomain_obj.status = status
            subdomain_obj.title = title
            subdomain_obj.server = server
            subdomain_obj.save()
            
            # 记录操作日志
            try:
                user_id = request.session.get('user_id')
                if user_id:
                    user = User.objects.get(id=user_id)
                    UserLog.objects.create(
                        user=user,
                        action='更新子域名',
                        ip=request.META.get('REMOTE_ADDR'),
                        details=f'更新子域名：{subdomain}.{domain}'
                    )
            except Exception as log_error:
                print(f"记录日志错误: {str(log_error)}")
            
            # 返回成功响应
            return JsonResponse({
                'code': 200,
                'msg': '更新子域名成功',
                'data': {
                    'id': subdomain_obj.id,
                    'domain': subdomain_obj.domain,
                    'subdomain': subdomain_obj.subdomain,
                    'ip': subdomain_obj.ip,
                    'status': subdomain_obj.status,
                    'title': subdomain_obj.title,
                    'server': subdomain_obj.server,
                    'create_time': subdomain_obj.create_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'update_time': subdomain_obj.update_time.strftime('%Y-%m-%d %H:%M:%S')
                }
            })
        except Exception as e:
            # 返回错误响应
            return JsonResponse({'code': 500, 'msg': f'更新子域名失败：{str(e)}'})
    
    def delete(self, request, subdomain_id=None):
        """删除子域名"""
        try:
            # 检查子域名ID
            if not subdomain_id:
                return JsonResponse({'code': 400, 'msg': '缺少子域名ID'})
            
            # 检查子域名是否存在
            try:
                subdomain_obj = Subdomain.objects.get(id=subdomain_id)
            except Subdomain.DoesNotExist:
                return JsonResponse({'code': 404, 'msg': '子域名不存在'})
            
            # 记录子域名信息用于日志
            domain = subdomain_obj.domain
            subdomain = subdomain_obj.subdomain
            
            # 删除子域名
            subdomain_obj.delete()
            
            # 记录操作日志
            try:
                user_id = request.session.get('user_id')
                if user_id:
                    user = User.objects.get(id=user_id)
                    UserLog.objects.create(
                        user=user,
                        action='删除子域名',
                        ip=request.META.get('REMOTE_ADDR'),
                        details=f'删除子域名：{subdomain}.{domain}'
                    )
            except Exception as log_error:
                print(f"记录日志错误: {str(log_error)}")
            
            # 返回成功响应
            return JsonResponse({'code': 200, 'msg': '删除子域名成功'})
        except Exception as e:
            # 返回错误响应
            return JsonResponse({'code': 500, 'msg': f'删除子域名失败：{str(e)}'})

# POC分类管理页面视图
class PocCategoryView(View):
    """POC分类页面视图"""
    def get(self, request):
        """渲染POC分类页面"""
        return render(request, 'poc_category.html', {'username': request.session.get('username', '')})

# POC管理页面视图
class PocManagementView(View):
    """POC管理页面视图"""
    def get(self, request):
        """渲染POC管理页面"""
        return render(request, 'poc_management.html', {'username': request.session.get('username', '')})

# POC分类API
class PocCategoryApiView(View):
    """POC分类API，提供POC分类的增删改查功能"""
    
    def get(self, request, category_id=None):
        """获取POC分类列表或单个POC分类信息"""
        try:
            # 如果提供了分类ID，则返回单个分类信息
            if category_id:
                try:
                    category = PocCategory.objects.get(id=category_id)
                    return JsonResponse({
                        'code': 200,
                        'msg': '获取POC分类成功',
                        'data': {
                            'id': category.id,
                            'name': category.name,
                            'description': category.description,
                            'create_time': category.create_time.strftime('%Y-%m-%d %H:%M:%S'),
                            'update_time': category.update_time.strftime('%Y-%m-%d %H:%M:%S')
                        }
                    })
                except PocCategory.DoesNotExist:
                    return JsonResponse({'code': 404, 'msg': 'POC分类不存在'})
            
            # 否则返回分类列表
            page = int(request.GET.get('page', 1))
            limit = int(request.GET.get('limit', 10))
            
            # 获取总数
            count = PocCategory.objects.count()
            
            # 分页查询
            categories = PocCategory.objects.all().order_by('id')[(page-1)*limit:page*limit]
            
            # 构造返回数据
            data = []
            for item in categories:
                data.append({
                    'id': item.id,
                    'name': item.name,
                    'description': item.description,
                    'create_time': item.create_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'update_time': item.update_time.strftime('%Y-%m-%d %H:%M:%S')
                })
            
            # 返回成功响应
            return JsonResponse({
                'code': 200,
                'msg': '获取POC分类列表成功',
                'count': count,
                'data': data
            })
        except Exception as e:
            # 返回错误响应
            return JsonResponse({
                'code': 500,
                'msg': f'获取POC分类列表失败：{str(e)}',
                'count': 0,
                'data': []
            })
    
    def post(self, request):
        """添加POC分类"""
        try:
            # 解析请求数据
            data = json.loads(request.body)
            name = data.get('name', '').strip()
            description = data.get('description', '').strip()
            
            # 验证必填字段
            if not name:
                return JsonResponse({'code': 400, 'msg': '分类名称不能为空'})
            
            # 检查是否已存在
            if PocCategory.objects.filter(name=name).exists():
                return JsonResponse({'code': 400, 'msg': '该分类名称已存在'})
            
            # 创建分类
            category = PocCategory.objects.create(
                name=name,
                description=description
            )
            
            # 记录操作日志
            try:
                user_id = request.session.get('user_id')
                if user_id:
                    user = User.objects.get(id=user_id)
                    UserLog.objects.create(
                        user=user,
                        action='添加POC分类',
                        ip=request.META.get('REMOTE_ADDR'),
                        details=f'添加POC分类：{name}'
                    )
            except Exception as log_error:
                print(f"记录日志错误: {str(log_error)}")
            
            # 返回成功响应
            return JsonResponse({
                'code': 200,
                'msg': '添加POC分类成功',
                'data': {
                    'id': category.id,
                    'name': category.name,
                    'description': category.description,
                    'create_time': category.create_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'update_time': category.update_time.strftime('%Y-%m-%d %H:%M:%S')
                }
            })
        except Exception as e:
            # 返回错误响应
            return JsonResponse({'code': 500, 'msg': f'添加POC分类失败：{str(e)}'})
    
    def put(self, request, category_id):
        """更新POC分类"""
        try:
            # 检查分类是否存在
            try:
                category = PocCategory.objects.get(id=category_id)
            except PocCategory.DoesNotExist:
                return JsonResponse({'code': 404, 'msg': 'POC分类不存在'})
            
            # 解析请求数据
            data = json.loads(request.body)
            name = data.get('name', '').strip()
            description = data.get('description', '').strip()
            
            # 验证必填字段
            if not name:
                return JsonResponse({'code': 400, 'msg': '分类名称不能为空'})
            
            # 检查名称是否已存在（排除当前分类）
            if PocCategory.objects.filter(name=name).exclude(id=category_id).exists():
                return JsonResponse({'code': 400, 'msg': '该分类名称已存在'})
            
            # 更新分类
            category.name = name
            category.description = description
            category.save()
            
            # 记录操作日志
            try:
                user_id = request.session.get('user_id')
                if user_id:
                    user = User.objects.get(id=user_id)
                    UserLog.objects.create(
                        user=user,
                        action='更新POC分类',
                        ip=request.META.get('REMOTE_ADDR'),
                        details=f'更新POC分类：{name}'
                    )
            except Exception as log_error:
                print(f"记录日志错误: {str(log_error)}")
            
            # 返回成功响应
            return JsonResponse({
                'code': 200,
                'msg': '更新POC分类成功',
                'data': {
                    'id': category.id,
                    'name': category.name,
                    'description': category.description,
                    'create_time': category.create_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'update_time': category.update_time.strftime('%Y-%m-%d %H:%M:%S')
                }
            })
        except Exception as e:
            # 返回错误响应
            return JsonResponse({'code': 500, 'msg': f'更新POC分类失败：{str(e)}'})
    
    def delete(self, request, category_id):
        """删除POC分类"""
        try:
            # 检查分类是否存在
            try:
                category = PocCategory.objects.get(id=category_id)
            except PocCategory.DoesNotExist:
                return JsonResponse({'code': 404, 'msg': 'POC分类不存在'})
            
            # 检查是否有关联的POC
            if Poc.objects.filter(category=category).exists():
                return JsonResponse({'code': 400, 'msg': '该分类下有POC，无法删除'})
            
            # 记录操作日志
            try:
                user_id = request.session.get('user_id')
                if user_id:
                    user = User.objects.get(id=user_id)
                    UserLog.objects.create(
                        user=user,
                        action='删除POC分类',
                        ip=request.META.get('REMOTE_ADDR'),
                        details=f'删除POC分类：{category.name}'
                    )
            except Exception as log_error:
                print(f"记录日志错误: {str(log_error)}")
            
            # 删除分类
            category.delete()
            
            # 返回成功响应
            return JsonResponse({'code': 200, 'msg': '删除POC分类成功'})
        except Exception as e:
            # 返回错误响应
            return JsonResponse({'code': 500, 'msg': f'删除POC分类失败：{str(e)}'})

# POC API
class PocApiView(View):
    """POC API，提供POC的增删改查功能"""
    
    def get(self, request, poc_id=None):
        """获取POC列表或单个POC信息"""
        try:
            # 如果提供了POC ID，则返回单个POC信息
            if poc_id:
                try:
                    poc = Poc.objects.get(id=poc_id)
                    return JsonResponse({
                        'code': 200,
                        'msg': '获取POC成功',
                        'data': {
                            'id': poc.id,
                            'name': poc.name,
                            'category_id': poc.category.id,
                            'category_name': poc.category.name,
                            'template': poc.template,
                            'severity': poc.severity,
                            'description': poc.description,
                            'create_time': poc.create_time.strftime('%Y-%m-%d %H:%M:%S'),
                            'update_time': poc.update_time.strftime('%Y-%m-%d %H:%M:%S')
                        }
                    })
                except Poc.DoesNotExist:
                    return JsonResponse({'code': 404, 'msg': 'POC不存在'})
            
            # 否则返回POC列表
            page = int(request.GET.get('page', 1))
            limit = int(request.GET.get('limit', 10))
            name = request.GET.get('name', '')
            category_id = request.GET.get('category_id', '')
            severity = request.GET.get('severity', '')
            
            # 构建查询条件
            query = Poc.objects.all()
            if name:
                query = query.filter(name__icontains=name)
            if category_id:
                query = query.filter(category_id=category_id)
            if severity:
                query = query.filter(severity=severity)
            
            # 获取总数
            count = query.count()
            
            # 分页查询
            pocs = query.order_by('id')[(page-1)*limit:page*limit]
            
            # 构造返回数据
            data = []
            for item in pocs:
                data.append({
                    'id': item.id,
                    'name': item.name,
                    'category_id': item.category.id,
                    'category_name': item.category.name,
                    'severity': item.severity,
                    'description': item.description,
                    'create_time': item.create_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'update_time': item.update_time.strftime('%Y-%m-%d %H:%M:%S')
                })
            
            # 返回成功响应
            return JsonResponse({
                'code': 200,
                'msg': '获取POC列表成功',
                'count': count,
                'data': data
            })
        except Exception as e:
            # 返回错误响应
            return JsonResponse({
                'code': 500,
                'msg': f'获取POC列表失败：{str(e)}',
                'count': 0,
                'data': []
            })
    
    def post(self, request):
        """添加POC"""
        try:
            # 解析请求数据
            data = json.loads(request.body)
            name = data.get('name', '').strip()
            category_id = data.get('category_id')
            template = data.get('template', '').strip()
            severity = data.get('severity', 'medium')
            description = data.get('description', '').strip()
            
            # 验证必填字段
            if not name:
                return JsonResponse({'code': 400, 'msg': 'POC名称不能为空'})
            if not category_id:
                return JsonResponse({'code': 400, 'msg': '请选择POC分类'})
            if not template:
                return JsonResponse({'code': 400, 'msg': 'Nuclei模板不能为空'})
            
            # 检查分类是否存在
            try:
                category = PocCategory.objects.get(id=category_id)
            except PocCategory.DoesNotExist:
                return JsonResponse({'code': 400, 'msg': '所选分类不存在'})
            
            # 创建POC
            poc = Poc.objects.create(
                name=name,
                category=category,
                template=template,
                severity=severity,
                description=description
            )
            
            # 记录操作日志
            try:
                user_id = request.session.get('user_id')
                if user_id:
                    user = User.objects.get(id=user_id)
                    UserLog.objects.create(
                        user=user,
                        action='添加POC',
                        ip=request.META.get('REMOTE_ADDR'),
                        details=f'添加POC：{name}'
                    )
            except Exception as log_error:
                print(f"记录日志错误: {str(log_error)}")
            
            # 返回成功响应
            return JsonResponse({
                'code': 200,
                'msg': '添加POC成功',
                'data': {
                    'id': poc.id,
                    'name': poc.name,
                    'category_id': poc.category.id,
                    'category_name': poc.category.name,
                    'template': poc.template,
                    'severity': poc.severity,
                    'description': poc.description,
                    'create_time': poc.create_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'update_time': poc.update_time.strftime('%Y-%m-%d %H:%M:%S')
                }
            })
        except Exception as e:
            # 返回错误响应
            return JsonResponse({'code': 500, 'msg': f'添加POC失败：{str(e)}'})
    
    def put(self, request, poc_id):
        """更新POC"""
        try:
            # 检查POC是否存在
            try:
                poc = Poc.objects.get(id=poc_id)
            except Poc.DoesNotExist:
                return JsonResponse({'code': 404, 'msg': 'POC不存在'})
            
            # 解析请求数据
            data = json.loads(request.body)
            name = data.get('name', '').strip()
            category_id = data.get('category_id')
            template = data.get('template', '').strip()
            severity = data.get('severity', 'medium')
            description = data.get('description', '').strip()
            
            # 验证必填字段
            if not name:
                return JsonResponse({'code': 400, 'msg': 'POC名称不能为空'})
            if not category_id:
                return JsonResponse({'code': 400, 'msg': '请选择POC分类'})
            if not template:
                return JsonResponse({'code': 400, 'msg': 'Nuclei模板不能为空'})
            
            # 检查分类是否存在
            try:
                category = PocCategory.objects.get(id=category_id)
            except PocCategory.DoesNotExist:
                return JsonResponse({'code': 400, 'msg': '所选分类不存在'})
            
            # 更新POC
            poc.name = name
            poc.category = category
            poc.template = template
            poc.severity = severity
            poc.description = description
            poc.save()
            
            # 记录操作日志
            try:
                user_id = request.session.get('user_id')
                if user_id:
                    user = User.objects.get(id=user_id)
                    UserLog.objects.create(
                        user=user,
                        action='更新POC',
                        ip=request.META.get('REMOTE_ADDR'),
                        details=f'更新POC：{name}'
                    )
            except Exception as log_error:
                print(f"记录日志错误: {str(log_error)}")
            
            # 返回成功响应
            return JsonResponse({
                'code': 200,
                'msg': '更新POC成功',
                'data': {
                    'id': poc.id,
                    'name': poc.name,
                    'category_id': poc.category.id,
                    'category_name': poc.category.name,
                    'template': poc.template,
                    'severity': poc.severity,
                    'description': poc.description,
                    'create_time': poc.create_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'update_time': poc.update_time.strftime('%Y-%m-%d %H:%M:%S')
                }
            })
        except Exception as e:
            # 返回错误响应
            return JsonResponse({'code': 500, 'msg': f'更新POC失败：{str(e)}'})
    
    def delete(self, request, poc_id):
        """删除POC"""
        try:
            # 检查POC是否存在
            try:
                poc = Poc.objects.get(id=poc_id)
            except Poc.DoesNotExist:
                return JsonResponse({'code': 404, 'msg': 'POC不存在'})
            
            # 记录操作日志
            try:
                user_id = request.session.get('user_id')
                if user_id:
                    user = User.objects.get(id=user_id)
                    UserLog.objects.create(
                        user=user,
                        action='删除POC',
                        ip=request.META.get('REMOTE_ADDR'),
                        details=f'删除POC：{poc.name}'
                    )
            except Exception as log_error:
                print(f"记录日志错误: {str(log_error)}")
            
            # 删除POC
            poc.delete()
            
            # 返回成功响应
            return JsonResponse({'code': 200, 'msg': '删除POC成功'})
        except Exception as e:
            # 返回错误响应
            return JsonResponse({'code': 500, 'msg': f'删除POC失败：{str(e)}'})