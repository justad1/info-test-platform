import json
import os
import subprocess
import time
import logging
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
            
            # 生成报告标题
            title = f"端口扫描报告 - {scan.target} - {scan.start_time.strftime('%Y-%m-%d %H:%M:%S')}"
            
            # 解析扫描结果
            result_data = json.loads(scan.result) if scan.result else {}
            
            # 生成报告内容
            content = {
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
            }
            
            # 创建扫描报告
            report = ScanReport.objects.create(
                title=title,
                report_type='portscan',
                target=scan.target,
                scan_time=scan.start_time,
                content=json.dumps(content, ensure_ascii=False)
            )
            
            return JsonResponse({
                'code': 0,
                'msg': '生成报告成功',
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
        """执行端口扫描"""
        try:
            # 解析请求数据
            data = json.loads(request.body)
            logger.info(f"接收到的扫描请求数据: {data}")
            
            # 处理目标主机数据
            if isinstance(data.get('hosts'), str):
                # 如果hosts是字符串，按换行符分割
                hosts = [h.strip() for h in data['hosts'].split('\n') if h.strip()]
                data['hosts'] = hosts
            
            # 检查naabu是否存在
            if not os.path.exists(self.naabu_path):
                logger.error(f"Naabu工具不存在: {self.naabu_path}")
                return JsonResponse({
                    'code': 500,
                    'msg': 'Naabu工具不存在',
                    'data': None
                })
            
            # 检查naabu是否可执行
            if not os.access(self.naabu_path, os.X_OK):
                logger.error(f"Naabu工具没有执行权限: {self.naabu_path}")
                try:
                    os.chmod(self.naabu_path, 0o755)
                    logger.info("已添加执行权限")
                except Exception as e:
                    logger.error(f"添加执行权限失败: {str(e)}")
                    return JsonResponse({
                        'code': 500,
                        'msg': 'Naabu工具没有执行权限',
                        'data': None
                    })
            
            # 构建命令
            cmd, targets = self.build_command(data)
            logger.info(f"构建的命令: {' '.join(cmd)}")
            
            if not targets:
                return JsonResponse({
                    'code': 400,
                    'msg': '请输入有效的目标主机',
                    'data': None
                })
            
            # 创建扫描记录
            scan_record = PortScan.objects.create(
                target=', '.join(targets),
                scan_type='connect',
                ports=data.get('custom_ports') or f"Top {data.get('top_ports', '100')}",
                status='running'
            )
            
            # 记录开始时间
            start_time = time.time()
            
            try:
                # 执行扫描
                logger.info(f"开始执行命令，工作目录: {os.getcwd()}")
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    cwd=os.path.dirname(self.naabu_path)  # 设置工作目录为naabu所在目录
                )
                
                # 获取输出
                stdout, stderr = process.communicate()
                return_code = process.returncode
                
                # 合并stdout和stderr的输出进行处理
                output = stdout + stderr
                logger.info(f"命令返回码: {return_code}")
                logger.info(f"命令输出: {output}")
                
                # 解析结果
                results, port_distribution, service_distribution = self.parse_results(output)
                logger.info(f"解析到的结果数量: {len(results)}")
                
                if not results:
                    logger.warning("没有扫描到开放端口")
                
            except Exception as e:
                logger.exception("命令执行异常")
                scan_record.status = 'failed'
                scan_record.save()
                return JsonResponse({
                    'code': 500,
                    'msg': f'命令执行失败：{str(e)}',
                    'data': None
                })
            
            # 计算扫描时间
            duration = time.time() - start_time
            
            # 更新扫描记录
            scan_record.status = 'completed'
            scan_record.result = json.dumps({
                'results': results,
                'port_distribution': port_distribution,
                'service_distribution': service_distribution
            })
            scan_record.end_time = timezone.now()
            scan_record.save()
            
            # 统计信息
            stats = {
                'host_count': len(set(r['host'] for r in results)),
                'port_count': len(results),
                'duration': f"{duration:.2f}s",
                'port_distribution': port_distribution,
                'service_distribution': service_distribution
            }
            
            # 保存结果到会话，用于导出
            request.session['last_portscan_results'] = results
            
            # 记录用户操作日志
            user_id = request.session.get('user_id')
            if user_id:
                from .models import User
                user = User.objects.get(id=user_id)
                UserLog.objects.create(
                    user=user,
                    action='执行端口扫描',
                    ip=get_client_ip(request),
                    details=f'扫描目标：{", ".join(targets)}'
                )
            
            return JsonResponse({
                'code': 0,
                'msg': '扫描完成',
                'data': {
                    'results': results,
                    'stats': stats
                }
            })
        
        except Exception as e:
            logger.exception("端口扫描失败")
            if 'scan_record' in locals():
                scan_record.status = 'failed'
                scan_record.save()
            
            return JsonResponse({
                'code': 500,
                'msg': f'扫描失败：{str(e)}',
                'data': None
            })
    
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
                csv_content += f"{result['host']},{result['port']},{result['protocol']},{result['service']},{result['version']},{result['banner']}\n"
            
            # 创建响应
            response = HttpResponse(csv_content, content_type='text/csv')
            response['Content-Disposition'] = f'attachment; filename="portscan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'
            
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
