import json
import os
import subprocess
import time
import logging
import threading
from django.shortcuts import render
from django.views import View
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from datetime import datetime

from .models import UserLog, PortScan
from .models_report import ScanReport
from .decorators import login_required, api_login_required
from .utils import get_client_ip

logger = logging.getLogger(__name__)

# 端口扫描页面视图
@method_decorator(login_required, name='dispatch')
class PortScanView(View):
    """端口扫描页面"""
    def get(self, request):
        return render(request, 'portscan.html')

# 端口扫描API
@method_decorator(csrf_exempt, name='dispatch')
@method_decorator(api_login_required, name='dispatch')
class PortScanApiView(View):
    """端口扫描API"""
    
    def __init__(self):
        super().__init__()
        self.naabu_path = os.path.join(settings.BASE_DIR, 'sectools', 'naabu', 'naabu')
    
    def build_command(self, params):
        """构建naabu命令"""
        cmd = [self.naabu_path]
        
        # 添加目标
        if params.get('hosts'):
            targets = []
            for host in params['hosts']:
                host = host.strip()
                if host:
                    targets.append(host)
                    cmd.extend(['-host', host])
        
        # 添加排除目标
        if params.get('exclude_hosts'):
            for host in params['exclude_hosts']:
                if host.strip():
                    cmd.extend(['-exclude-hosts', host.strip()])
        
        # 端口配置
        if params.get('port_type') == 'top':
            cmd.extend(['-top-ports', params.get('top_ports', '100')])
        elif params.get('custom_ports'):
            cmd.extend(['-p', params['custom_ports']])
        
        # 排除端口
        if params.get('exclude_ports'):
            cmd.extend(['-exclude-ports', params['exclude_ports']])
        
        # 扫描选项
        if params.get('scan_all_ips'):
            cmd.append('-scan-all-ips')
        if params.get('exclude_cdn'):
            cmd.append('-exclude-cdn')
        if params.get('service_detection'):
            cmd.append('-sV')
        
        # 性能配置
        cmd.extend([
            '-c', str(params.get('concurrency', 25)),
            '-timeout', str(params.get('timeout', 1000)),
            '-retries', str(params.get('retries', 3))
        ])
        
        return cmd, targets
    
    def parse_results(self, output):
        """解析naabu输出结果"""
        results = []
        port_distribution = {}
        service_distribution = {}
        
        for line in output.splitlines():
            try:
                # 跳过信息行和空行
                if '[INF]' in line or not line.strip():
                    continue
                
                # 处理host:port格式
                if ':' in line:
                    host, port = line.strip().split(':')
                    try:
                        port = int(port)
                        result = {
                            'host': host,
                            'port': port,
                            'protocol': 'tcp',
                            'service': '',
                            'version': '',
                            'banner': ''
                        }
                        results.append(result)
                        
                        # 更新端口分布
                        port_str = str(port)
                        port_distribution[port_str] = port_distribution.get(port_str, 0) + 1
                        
                    except ValueError:
                        logger.warning(f"无效的端口号: {port}")
                        continue
            except Exception as e:
                logger.debug(f"解析行失败: {line}, 错误: {str(e)}")
                continue
        
        return results, port_distribution, service_distribution
    
    def generate_report(self, request):
        """生成扫描报告"""
        try:
            scan_id = request.POST.get('scan_id')
            if not scan_id:
                return JsonResponse({
                    'code': 400,
                    'msg': '缺少扫描ID',
                    'data': None
                })
            
            # 获取扫描记录
            scan = PortScan.objects.get(id=scan_id)
            
            # 检查扫描状态
            if scan.status != 'completed':
                return JsonResponse({
                    'code': 400,
                    'msg': '只能为已完成的扫描生成报告',
                    'data': None
                })
            
            # 解析扫描结果
            result_data = json.loads(scan.result) if scan.result else {}
            
            # 创建扫描报告
            report = ScanReport.objects.create(
                title=f"端口扫描报告 - {scan.target} - {scan.start_time.strftime('%Y-%m-%d %H:%M:%S')}",
                report_type='portscan',
                target=scan.target,
                scan_time=scan.start_time,
                content=json.dumps({
                    'scan_info': {
                        'target': scan.target,
                        'scan_type': scan.scan_type,
                        'ports': scan.ports,
                        'start_time': scan.start_time.strftime('%Y-%m-%d %H:%M:%S'),
                        'end_time': scan.end_time.strftime('%Y-%m-%d %H:%M:%S') if scan.end_time else '',
                        'status': scan.status
                    },
                    'open_ports': result_data.get('open_ports', []),
                    'service_info': result_data.get('service_info', {})
                }, ensure_ascii=False)
            )
            
            # 记录用户操作日志
            UserLog.objects.create(
                username=request.session.get('username', 'unknown'),
                action='生成端口扫描报告',
                ip=get_client_ip(request),
                content=json.dumps({
                    'scan_id': scan.id,
                    'report_id': report.id,
                    'target': scan.target
                }, ensure_ascii=False)
            )
            
            return JsonResponse({
                'code': 0,
                'msg': '报告生成成功',
                'data': {
                    'report_id': report.id
                }
            })
            
        except PortScan.DoesNotExist:
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
    
    def post(self, request):
        """处理端口扫描请求"""
        try:
            action = request.POST.get('action')
            
            # 生成报告
            if action == 'report':
                return self.generate_report(request)
            
            # 开始扫描
            body_data = json.loads(request.body)
            target = body_data.get('target', '').strip()
            scan_type = body_data.get('scan_type', 'tcp')
            ports = body_data.get('ports', '1-1000')
            threads = body_data.get('threads', 10)
            timeout = body_data.get('timeout', 5)
            
            # 验证参数
            if not target:
                return JsonResponse({'code': 400, 'msg': '请输入扫描目标', 'data': None})
            
            # 验证目标格式（IP地址或域名）
            if not self.is_valid_target(target):
                return JsonResponse({'code': 400, 'msg': '无效的扫描目标格式', 'data': None})
            
            # 创建扫描任务
            task = PortScan.objects.create(
                target=target,
                scan_type=scan_type,
                ports=ports,
                threads=int(threads),
                timeout=int(timeout),
                status='running',
                start_time=timezone.now()
            )
            
            # 记录用户操作日志
            UserLog.objects.create(
                username=request.session.get('username', 'unknown'),
                action='创建端口扫描任务',
                ip=get_client_ip(request),
                content=json.dumps({
                    'task_id': task.id,
                    'target': target,
                    'scan_type': scan_type,
                    'ports': ports
                }, ensure_ascii=False)
            )
            
            # 启动扫描线程
            t = threading.Thread(target=self.run_scan, args=(task,))
            t.daemon = True
            t.start()
            
            return JsonResponse({
                'code': 0,
                'msg': '扫描任务已创建',
                'data': {
                    'task_id': task.id
                }
            })
            
        except Exception as e:
            return JsonResponse({'code': 500, 'msg': str(e), 'data': None})
    
    def get(self, request, scan_id=None):
        """处理GET请求，根据URL路径不同执行不同操作
        1. /api/portscan/export/ - 导出扫描结果
        2. /api/portscan/history/ - 获取历史记录列表
        3. /api/portscan/history/<scan_id>/ - 获取特定历史记录详情
        """
        # 获取当前路径
        path = request.path
        
        # 导出扫描结果
        if 'export' in path:
            return self.export_results(request)
        # 获取特定历史记录详情
        elif 'history' in path and scan_id:
            return self.get_history_detail(request, scan_id)
        # 获取历史记录列表
        elif 'history' in path:
            return self.get_history_list(request)
        # 默认返回错误
        else:
            return JsonResponse({
                'code': 404,
                'msg': '未找到请求的资源',
                'data': None
            })
    
    def export_results(self, request):
        """导出扫描结果"""
        try:
            # 获取最近的扫描结果
            results = request.session.get('last_portscan_results', [])
            
            # 生成CSV内容
            csv_content = "主机,端口,协议,服务,版本,横幅信息\n"
            for result in results:
                # 处理可能包含逗号和换行符的字段
                host = result.get('host', '').replace(',', '，')
                port = result.get('port', '')
                protocol = result.get('protocol', '').replace(',', '，')
                service = result.get('service', '').replace(',', '，')
                version = result.get('version', '').replace(',', '，')
                banner = result.get('banner', '').replace(',', '，').replace('\n', ' ')
                
                csv_content += f"{host},{port},{protocol},{service},{version},{banner}\n"
            
            # 创建响应，使用UTF-8-SIG编码（带BOM），确保Excel能正确识别中文
            response = HttpResponse(content_type='text/csv; charset=utf-8-sig')
            response['Content-Disposition'] = f'attachment; filename="portscan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'
            
            # 写入UTF-8-SIG BOM
            response.write('\ufeff')
            
            # 写入CSV内容
            response.write(csv_content)
            
            return response
            
        except Exception as e:
            logger.exception("导出扫描结果失败")
            return JsonResponse({
                'code': 500,
                'msg': f'导出失败：{str(e)}',
                'data': None
            })
    
    def get_history_list(self, request):
        """获取历史记录列表"""
        try:
            # 获取分页参数
            page = int(request.GET.get('page', 1))
            limit = int(request.GET.get('limit', 10))
            
            # 计算偏移量
            offset = (page - 1) * limit
            
            # 获取总记录数
            total = PortScan.objects.count()
            
            # 获取分页数据
            scans = PortScan.objects.all().order_by('-start_time')[offset:offset+limit]
            
            # 构建响应数据
            data = []
            for scan in scans:
                # 解析结果JSON
                result_data = {}
                if scan.result:
                    try:
                        result_data = json.loads(scan.result)
                    except:
                        pass
                
                # 计算端口数量
                port_count = 0
                if 'results' in result_data:
                    port_count = len(result_data['results'])
                
                data.append({
                    'id': scan.id,
                    'target': scan.target,
                    'scan_type': scan.scan_type,
                    'ports': scan.ports,
                    'status': scan.status,
                    'port_count': port_count,
                    'start_time': scan.start_time.strftime('%Y-%m-%d %H:%M:%S') if scan.start_time else '',
                    'end_time': scan.end_time.strftime('%Y-%m-%d %H:%M:%S') if scan.end_time else ''
                })
            
            return JsonResponse({
                'code': 0,
                'msg': '',
                'count': total,
                'data': data
            })
            
        except Exception as e:
            logger.exception("获取历史记录列表失败")
            return JsonResponse({
                'code': 500,
                'msg': f'获取历史记录列表失败：{str(e)}',
                'data': None
            })
    
    def get_history_detail(self, request, scan_id):
        """获取特定历史记录详情"""
        try:
            # 获取扫描记录
            scan = PortScan.objects.get(id=scan_id)
            
            # 解析结果JSON
            result_data = {}
            if scan.result:
                try:
                    result_data = json.loads(scan.result)
                except:
                    pass
            
            # 构建响应数据
            data = {
                'id': scan.id,
                'target': scan.target,
                'scan_type': scan.scan_type,
                'ports': scan.ports,
                'status': scan.status,
                'start_time': scan.start_time.strftime('%Y-%m-%d %H:%M:%S') if scan.start_time else '',
                'end_time': scan.end_time.strftime('%Y-%m-%d %H:%M:%S') if scan.end_time else '',
                'results': result_data.get('results', []),
                'port_distribution': result_data.get('port_distribution', {}),
                'service_distribution': result_data.get('service_distribution', {})
            }
            
            return JsonResponse({
                'code': 0,
                'msg': '',
                'data': data
            })
            
        except PortScan.DoesNotExist:
            return JsonResponse({
                'code': 404,
                'msg': '未找到指定的扫描记录',
                'data': None
            })
        except Exception as e:
            logger.exception("获取历史记录详情失败")
            return JsonResponse({
                'code': 500,
                'msg': f'获取历史记录详情失败：{str(e)}',
                'data': None
            })
