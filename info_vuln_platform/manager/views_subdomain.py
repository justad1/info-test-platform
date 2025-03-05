import json
from django.shortcuts import render
from django.views import View
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
import logging

from .models import Subdomain, UserLog
from .models_report import ScanReport
from .decorators import login_required

# 配置logger
logger = logging.getLogger(__name__)

# 获取客户端IP
def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

# 子域名管理视图
@method_decorator(login_required, name='dispatch')
class SubdomainView(View):
    """子域名管理页面"""
    def get(self, request):
        return render(request, 'subdomain.html')

# 子域名API
@method_decorator(login_required, name='dispatch')
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
            start = (page - 1) * limit
            end = page * limit
            
            # 获取分页数据
            subdomains = query[start:end]
            
            # 准备响应数据
            data = []
            for item in subdomains:
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
            UserLog.objects.create(
                user=request.user,
                action='添加子域名',
                ip=get_client_ip(request),
                details=f'添加子域名：{subdomain}.{domain}'
            )
            
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
            UserLog.objects.create(
                user=request.user,
                action='更新子域名',
                ip=get_client_ip(request),
                details=f'更新子域名：{subdomain}.{domain}'
            )
            
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
            UserLog.objects.create(
                user=request.user,
                action='删除子域名',
                ip=get_client_ip(request),
                details=f'删除子域名：{subdomain}.{domain}'
            )
            
            # 返回成功响应
            return JsonResponse({'code': 200, 'msg': '删除子域名成功'})
        except Exception as e:
            # 返回错误响应
            return JsonResponse({'code': 500, 'msg': f'删除子域名失败：{str(e)}'})

    def generate_report(self, request):
        """生成子域名扫描报告"""
        try:
            scan_id = request.POST.get('scan_id')
            if not scan_id:
                return JsonResponse({
                    'code': 400,
                    'msg': '缺少扫描ID',
                    'data': None
                })
            
            # 获取扫描记录
            scan = Subdomain.objects.get(id=scan_id)
            
            # 生成报告标题
            title = f"子域名扫描报告 - {scan.domain} - {scan.create_time.strftime('%Y-%m-%d %H:%M:%S')}"
            
            # 生成报告内容
            content = {
                'scan_info': {
                    'domain': scan.domain,
                    'subdomain': scan.subdomain,
                    'ip': scan.ip,
                    'status': scan.status,
                    'title': scan.title,
                    'server': scan.server,
                    'create_time': scan.create_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'update_time': scan.update_time.strftime('%Y-%m-%d %H:%M:%S')
                }
            }
            
            # 创建扫描报告
            report = ScanReport.objects.create(
                title=title,
                report_type='subdomain',
                target=scan.domain,
                scan_time=scan.create_time,
                content=json.dumps(content, ensure_ascii=False)
            )
            
            return JsonResponse({
                'code': 0,
                'msg': '生成报告成功',
                'data': {
                    'report_id': report.id
                }
            })
            
        except Subdomain.DoesNotExist:
            return JsonResponse({
                'code': 404,
                'msg': '扫描记录不存在',
                'data': None
            })
        except Exception as e:
            logger.exception("生成报告失败")
            return JsonResponse({
                'code': 500,
                'msg': f'生成报告失败：{str(e)}',
                'data': None
            })
