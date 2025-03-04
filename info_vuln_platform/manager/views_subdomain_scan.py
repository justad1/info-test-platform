import json
import os
import subprocess
import time
import logging
from django.shortcuts import render
from django.views import View
from django.http import JsonResponse
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings

from .models import Subdomain
from .models_subdomain import SubdomainScan
from .decorators import login_required, api_login_required
from .utils import get_client_ip
from .models import UserLog

logger = logging.getLogger(__name__)

# 子域名扫描页面视图
@method_decorator(login_required, name='dispatch')
class SubdomainScanView(View):
    """子域名扫描页面"""
    def get(self, request):
        return render(request, 'subdomain_scan.html')

# 子域名扫描API
@method_decorator(csrf_exempt, name='dispatch')
@method_decorator(api_login_required, name='dispatch')
class SubdomainScanApiView(View):
    """子域名扫描API"""
    
    def __init__(self):
        super().__init__()
        self.subfinder_path = os.path.join(settings.BASE_DIR, 'sectools', 'subfinder', 'subfinder')
    
    def build_command(self, params):
        """构建subfinder命令"""
        cmd = [self.subfinder_path]
        
        # 添加目标域名
        domain = params.get('domain', '').strip()
        if not domain:
            raise ValueError('主域名不能为空')
        cmd.extend(['-d', domain])
        
        # 添加输出格式为JSON
        cmd.extend(['-oJ', '-silent'])
        
        return cmd, domain
    
    def run_scan(self, cmd, domain):
        """运行扫描"""
        # 创建扫描记录
        scan_record = SubdomainScan.objects.create(
            domain=domain,
            status='running'
        )
        
        try:
            # 运行命令
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # 获取输出
            stdout, stderr = process.communicate()
            
            # 检查是否有错误
            if process.returncode != 0:
                logger.error(f"Subfinder扫描失败: {stderr}")
                scan_record.status = 'failed'
                scan_record.result = stderr
                scan_record.end_time = timezone.now()
                scan_record.save()
                return scan_record, False
            
            # 处理扫描结果
            results = []
            found_count = 0
            
            # 解析JSON输出（每行一个JSON对象）
            for line in stdout.strip().split('\n'):
                if line:
                    try:
                        result = json.loads(line)
                        results.append(result)
                        found_count += 1
                        
                        # 保存到子域名表
                        subdomain_name = result.get('host', '').split('.', 1)[0]
                        if subdomain_name and domain:
                            # 检查是否已存在
                            if not Subdomain.objects.filter(domain=domain, subdomain=subdomain_name).exists():
                                Subdomain.objects.create(
                                    domain=domain,
                                    subdomain=subdomain_name,
                                    ip=result.get('ip', '')
                                )
                    except json.JSONDecodeError:
                        logger.warning(f"无法解析JSON行: {line}")
            
            # 更新扫描记录
            scan_record.status = 'completed'
            scan_record.result = json.dumps(results)
            scan_record.end_time = timezone.now()
            scan_record.found_count = found_count
            scan_record.save()
            
            return scan_record, True
            
        except Exception as e:
            logger.exception(f"子域名扫描异常: {str(e)}")
            scan_record.status = 'failed'
            scan_record.result = str(e)
            scan_record.end_time = timezone.now()
            scan_record.save()
            return scan_record, False
    
    def post(self, request):
        """开始扫描"""
        try:
            # 解析请求数据
            data = json.loads(request.body)
            domain = data.get('domain', '').strip()
            
            # 验证必填字段
            if not domain:
                return JsonResponse({'code': 400, 'msg': '主域名不能为空'})
            
            # 构建命令
            try:
                cmd, domain = self.build_command({'domain': domain})
            except ValueError as e:
                return JsonResponse({'code': 400, 'msg': str(e)})
            
            # 记录操作日志
            # 只有在用户已登录的情况下才创建用户日志
            if request.session.get('user_id'):
                from .models import User
                try:
                    user = User.objects.get(id=request.session.get('user_id'))
                    UserLog.objects.create(
                        user=user,
                        action='子域名扫描',
                        ip=get_client_ip(request),
                        details=f'扫描域名: {domain}'
                    )
                except User.DoesNotExist:
                    # 用户不存在，不创建日志
                    pass
            
            # 运行扫描
            scan_record, success = self.run_scan(cmd, domain)
            
            if success:
                return JsonResponse({
                    'code': 200,
                    'msg': '子域名扫描完成',
                    'data': {
                        'id': scan_record.id,
                        'domain': scan_record.domain,
                        'status': scan_record.status,
                        'start_time': scan_record.start_time.strftime('%Y-%m-%d %H:%M:%S'),
                        'end_time': scan_record.end_time.strftime('%Y-%m-%d %H:%M:%S') if scan_record.end_time else None,
                        'found_count': scan_record.found_count
                    }
                })
            else:
                return JsonResponse({
                    'code': 500,
                    'msg': '子域名扫描失败',
                    'data': {
                        'id': scan_record.id,
                        'domain': scan_record.domain,
                        'status': scan_record.status,
                        'error': scan_record.result
                    }
                })
                
        except Exception as e:
            logger.exception(f"子域名扫描异常: {str(e)}")
            return JsonResponse({'code': 500, 'msg': f'子域名扫描异常: {str(e)}'})
    
    def get(self, request, scan_id=None):
        """获取扫描历史或单个扫描记录"""
        try:
            # 如果提供了扫描ID，返回单个扫描记录
            if scan_id:
                try:
                    scan = SubdomainScan.objects.get(id=scan_id)
                    
                    # 解析结果
                    results = []
                    if scan.result:
                        try:
                            results = json.loads(scan.result)
                        except json.JSONDecodeError:
                            results = []
                    
                    return JsonResponse({
                        'code': 200,
                        'msg': '获取扫描记录成功',
                        'data': {
                            'id': scan.id,
                            'domain': scan.domain,
                            'status': scan.status,
                            'start_time': scan.start_time.strftime('%Y-%m-%d %H:%M:%S'),
                            'end_time': scan.end_time.strftime('%Y-%m-%d %H:%M:%S') if scan.end_time else None,
                            'found_count': scan.found_count,
                            'results': results
                        }
                    })
                except SubdomainScan.DoesNotExist:
                    return JsonResponse({'code': 404, 'msg': '扫描记录不存在'})
            
            # 获取查询参数
            page = int(request.GET.get('page', 1))
            limit = int(request.GET.get('limit', 10))
            domain = request.GET.get('domain', '')
            
            # 查询扫描记录
            query = SubdomainScan.objects.all()
            
            # 应用过滤条件
            if domain:
                query = query.filter(domain__icontains=domain)
            
            # 计算总数
            count = query.count()
            
            # 分页
            start = (page - 1) * limit
            end = page * limit
            
            # 获取分页数据
            scans = query[start:end]
            
            # 准备响应数据
            data = []
            for scan in scans:
                data.append({
                    'id': scan.id,
                    'domain': scan.domain,
                    'status': scan.status,
                    'start_time': scan.start_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'end_time': scan.end_time.strftime('%Y-%m-%d %H:%M:%S') if scan.end_time else None,
                    'found_count': scan.found_count
                })
            
            # 返回成功响应
            return JsonResponse({
                'code': 200,
                'msg': '获取扫描历史成功',
                'count': count,
                'data': data
            })
        except Exception as e:
            # 返回错误响应
            return JsonResponse({
                'code': 500,
                'msg': f'获取扫描历史失败：{str(e)}',
                'count': 0,
                'data': []
            })
