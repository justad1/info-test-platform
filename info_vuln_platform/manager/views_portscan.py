import json
import os
import subprocess
import time
import logging
import threading
import re
import ipaddress
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
    
    def is_valid_target(self, target):
        """验证目标格式是否为有效的IP地址或域名"""
        # 检查是否为有效IP地址
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            pass
        
        # 检查是否为有效域名
        domain_pattern = r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'
        return bool(re.match(domain_pattern, target))
    
    def build_command(self, params):
        """构建naabu命令，简化为直接调用方式"""
        cmd = [self.naabu_path]
        
        # 添加目标
        if params.get('target'):
            cmd.extend(['-host', params['target']])
        
        # 添加端口配置
        if params.get('ports'):
            ports = params['ports']
            # 处理top-ports参数
            if ports.startswith('top-'):
                cmd.extend(['-top-ports', ports[4:]])
            else:
                cmd.extend(['-p', ports])
        
        # 设置输出格式为JSON
        cmd.append('-json')
        
        # 添加基本性能参数
        cmd.extend(['-c', '25', '-timeout', '1000', '-retries', '3'])
        
        logger.info(f"naabu命令: {' '.join(cmd)}")
        return cmd
    
    def run_scan(self, task):
        """执行扫描任务，使用naabu工具执行端口扫描"""
        try:
            # 检查naabu工具是否存在
            if not os.path.exists(self.naabu_path):
                logger.error(f"naabu工具不存在: {self.naabu_path}")
                task.status = 'failed'
                task.result = json.dumps({'error': 'naabu工具不存在'}, ensure_ascii=False)
                task.end_time = timezone.now()
                task.save()
                return
            
            logger.info(f"naabu工具存在")
            
            # 构建命令行参数
            cmd = [self.naabu_path]
            
            # 添加目标
            cmd.extend(['-host', task.target])
            
            # 添加端口配置
            ports = task.ports
            if ports:
                if ports.startswith('top-'):
                    cmd.extend(['-top-ports', ports[4:]])
                else:
                    cmd.extend(['-p', ports])
            
            # 添加其他参数
            cmd.extend(['-c', '25'])  # 并发数
            cmd.extend(['-timeout', '1000'])  # 超时时间（毫秒）
            cmd.extend(['-retries', '3'])  # 重试次数
            
            # 设置输出为JSON格式
            cmd.append('-json')
            
            logger.debug(f"完整扫描命令: {' '.join(cmd)}")
            logger.info(f"执行扫描命令: {' '.join(cmd)}")
            
            # 设置工作目录
            work_dir = os.path.dirname(self.naabu_path)
            logger.info(f"工作目录: {work_dir}")
            
            # 执行命令
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True,
                cwd=work_dir
            )
            stdout, stderr = process.communicate()
            
            logger.info(f"命令执行结果: 返回码={process.returncode}")
            if stderr:
                logger.error(f"命令错误输出: {stderr}")
            logger.info(f"命令标准输出长度: {len(stdout)}")
            
            # 解析结果
            results = []
            port_distribution = {}
            service_distribution = {}
            
            if process.returncode == 0:
                logger.debug(f"naabu执行成功，开始解析结果: output_length={len(stdout)}")
                
                # 解析每一行JSON输出
                for line in stdout.splitlines():
                    line = line.strip()
                    if not line or line.startswith('['):
                        continue
                        
                    try:
                        result_json = json.loads(line)
                        if 'ip' in result_json and 'port' in result_json:
                            host = result_json.get('ip')
                            port = result_json.get('port')
                            
                            # 构建结果
                            result = {
                                'host': host,
                                'port': port,
                                'protocol': result_json.get('protocol', 'tcp'),
                                'service': result_json.get('service', ''),
                                'version': result_json.get('version', ''),
                                'banner': result_json.get('banner', '')
                            }
                            results.append(result)
                            
                            # 更新端口分布
                            port_str = str(port)
                            port_distribution[port_str] = port_distribution.get(port_str, 0) + 1
                            
                            # 更新服务分布
                            if result['service']:
                                service_distribution[result['service']] = service_distribution.get(result['service'], 0) + 1
                    except Exception as e:
                        logger.debug(f"解析JSON行失败: {line}, 错误: {str(e)}")
                        
                        # 尝试解析普通文本输出格式（如host:port）
                        try:
                            if ':' in line:
                                host, port = line.split(':', 1)
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
                                port_str = str(port)
                                port_distribution[port_str] = port_distribution.get(port_str, 0) + 1
                        except Exception as e2:
                            logger.debug(f"解析文本行失败: {line}, 错误: {str(e2)}")
            else:
                logger.error(f"naabu执行失败: {stderr}")
            
            # 保存结果
            task.status = 'completed'
            task.result = json.dumps({
                'results': results,
                'port_distribution': port_distribution,
                'service_distribution': service_distribution
            }, ensure_ascii=False)
            task.end_time = timezone.now()
            task.save()
            
            logger.info(f"扫描完成: 目标={task.target}, 开放端口数={len(results)}")
            
        except Exception as e:
            logger.exception(f"端口扫描失败: {str(e)}")
            task.status = 'failed'
            task.result = json.dumps({
                'error': str(e)
            }, ensure_ascii=False)
            task.end_time = timezone.now()
            task.save()
    
    def parse_results(self, output):
        """解析naabu输出结果"""
        results = []
        port_distribution = {}
        service_distribution = {}
        
        for line in output.splitlines():
            try:
                # 尝试解析JSON格式输出
                if line.strip() and not line.startswith('[INF]'):
                    try:
                        result_json = json.loads(line)
                        if 'ip' in result_json and 'port' in result_json:
                            host = result_json.get('ip')
                            port = result_json.get('port')
                            
                            result = {
                                'host': host,
                                'port': port,
                                'protocol': 'tcp',
                                'service': result_json.get('service', ''),
                                'version': result_json.get('version', ''),
                                'banner': result_json.get('banner', '')
                            }
                            results.append(result)
                            
                            # 更新端口分布
                            port_str = str(port)
                            port_distribution[port_str] = port_distribution.get(port_str, 0) + 1
                            
                            # 更新服务分布
                            if result['service']:
                                service_distribution[result['service']] = service_distribution.get(result['service'], 0) + 1
                                
                    except json.JSONDecodeError:
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
                    'open_ports': result_data.get('results', []),
                    'port_distribution': result_data.get('port_distribution', {}),
                    'service_distribution': result_data.get('service_distribution', {})
                }, ensure_ascii=False)
            )
            
            # 记录用户操作日志
            from .models import User
            user_id = request.session.get('user_id')
            if user_id:
                try:
                    user = User.objects.get(id=user_id)
                    UserLog.objects.create(
                        user=user,
                        action='生成端口扫描报告',
                        ip=get_client_ip(request),
                        details=json.dumps({
                            'scan_id': scan.id,
                            'report_id': report.id,
                            'target': scan.target
                        }, ensure_ascii=False)
                    )
                except User.DoesNotExist:
                    logger.warning(f"用户不存在: {user_id}")
            
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
    
    def save_results(self, request):
        """保存扫描结果到session，供导出使用"""
        try:
            results_json = request.POST.get('results')
            if results_json:
                results = json.loads(results_json)
                # 保存到session
                request.session['last_portscan_results'] = results
                return JsonResponse({'code': 0, 'msg': '结果已保存'})
            else:
                return JsonResponse({'code': 400, 'msg': '未提供结果数据'})
        except Exception as e:
            logger.exception("保存扫描结果失败")
            return JsonResponse({'code': 500, 'msg': f'保存失败：{str(e)}'})
    
    def post(self, request):
        """处理端口扫描请求"""
        try:
            # 检查是否为表单提交的报告请求
            action = request.POST.get('action')
            
            # 生成报告
            if action == 'report':
                return self.generate_report(request)
                
            # 保存结果到session
            if 'save-results' in request.path:
                return self.save_results(request)
            
            # 获取目标和端口
            try:
                body_data = json.loads(request.body)
            except json.JSONDecodeError:
                body_data = request.POST.dict() if request.POST else request.GET.dict()
            
            # 提取目标地址
            target = body_data.get('target', '')
            if not target:
                hosts = body_data.get('hosts', '')
                if hosts:
                    if isinstance(hosts, list) and hosts:
                        target = hosts[0]
                    elif isinstance(hosts, str) and hosts:
                        # 取第一行作为目标地址
                        target = hosts.splitlines()[0].strip()
            
            # 提取端口
            ports = '1-1000'  # 默认端口范围
            if body_data.get('port_type') == 'top':
                top_ports = body_data.get('top_ports', '100')
                if top_ports == 'full':
                    ports = '1-65535'
                else:
                    # 使用naabu的top-ports参数
                    ports = f"top-{top_ports}"
            elif body_data.get('custom_ports'):
                ports = body_data.get('custom_ports')
            
            # 验证目标
            if not target:
                return JsonResponse({'code': 400, 'msg': '请输入扫描目标', 'data': None})
            
            if not self.is_valid_target(target):
                return JsonResponse({'code': 400, 'msg': '无效的扫描目标格式', 'data': None})
            
            # 创建扫描任务
            task = PortScan.objects.create(
                target=target,
                scan_type='tcp',
                ports=ports,
                status='running',
                start_time=timezone.now()
            )
            
            # 记录日志
            from .models import User
            user_id = request.session.get('user_id')
            if user_id:
                try:
                    user = User.objects.get(id=user_id)
                    UserLog.objects.create(
                        user=user,
                        action='创建端口扫描任务',
                        ip=get_client_ip(request),
                        details=f"扫描目标：{target}，端口：{ports}"
                    )
                except User.DoesNotExist:
                    pass
            
            # 启动扫描线程
            t = threading.Thread(target=self.run_scan, args=(task,))
            t.daemon = True
            t.start()
            
            return JsonResponse({
                'code': 0,
                'msg': '扫描任务已创建',
                'data': {
                    'task_id': task.id,
                    'target': target,
                    'ports': ports,
                    'status': 'running'
                }
            })
            
        except Exception as e:
            logger.exception(f"处理端口扫描请求失败: {str(e)}")
            return JsonResponse({'code': 500, 'msg': str(e), 'data': None})
    
    def get_scan_status(self, request, scan_id):
        """获取扫描状态"""
        try:
            scan = PortScan.objects.get(id=scan_id)
            
            # 计算扫描时间
            duration = "0s"
            if scan.start_time:
                end_time = scan.end_time if scan.end_time else timezone.now()
                seconds = int((end_time - scan.start_time).total_seconds())
                duration = f"{seconds}s"
            
            # 解析结果JSON
            result_data = {}
            port_count = 0
            host_count = 0
            results = []
            port_distribution = {}
            service_distribution = {}
            
            if scan.result:
                try:
                    result_data = json.loads(scan.result)
                    if 'results' in result_data:
                        results = result_data['results']
                        port_count = len(results)
                        host_set = set()
                        for item in results:
                            host_set.add(item.get('host', ''))
                        host_count = len(host_set)
                    
                    port_distribution = result_data.get('port_distribution', {})
                    service_distribution = result_data.get('service_distribution', {})
                except:
                    logger.exception("解析扫描结果失败")
            
            return JsonResponse({
                'code': 0,
                'msg': '',
                'data': {
                    'id': scan.id,
                    'target': scan.target,
                    'scan_type': scan.scan_type,
                    'ports': scan.ports,
                    'status': scan.status,
                    'start_time': scan.start_time.strftime('%Y-%m-%d %H:%M:%S') if scan.start_time else '',
                    'end_time': scan.end_time.strftime('%Y-%m-%d %H:%M:%S') if scan.end_time else '',
                    'duration': duration,
                    'results': results,
                    'stats': {
                        'host_count': host_count,
                        'port_count': port_count,
                        'duration': duration,
                        'port_distribution': port_distribution,
                        'service_distribution': service_distribution
                    }
                }
            })
            
        except PortScan.DoesNotExist:
            return JsonResponse({
                'code': 404,
                'msg': '未找到指定的扫描记录',
                'data': None
            })
        except Exception as e:
            logger.exception("获取扫描状态失败")
            return JsonResponse({
                'code': 500,
                'msg': f'获取扫描状态失败：{str(e)}',
                'data': None
            })
            
    def get(self, request, scan_id=None):
        """处理GET请求，根据URL路径不同执行不同操作
        1. /api/portscan/export/ - 导出扫描结果
        2. /api/portscan/history/ - 获取历史记录列表
        3. /api/portscan/history/<scan_id>/ - 获取特定历史记录详情
        4. /api/portscan/status/<scan_id>/ - 获取扫描状态
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
        # 获取扫描状态
        elif 'status' in path and scan_id:
            return self.get_scan_status(request, scan_id)
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
            # 获取扫描ID（如果提供）
            scan_id = request.GET.get('id')
            results = []
            
            if scan_id:
                # 从数据库获取特定扫描的结果
                try:
                    scan = PortScan.objects.get(id=scan_id)
                    if scan.result:
                        result_data = json.loads(scan.result)
                        results = result_data.get('results', [])
                except PortScan.DoesNotExist:
                    logger.warning(f"找不到扫描记录: {scan_id}")
            else:
                # 尝试从会话中获取最近的扫描结果
                results = request.session.get('last_portscan_results', [])
                
                # 如果会话中没有结果，获取最新的扫描结果
                if not results:
                    latest_scan = PortScan.objects.filter(status='completed').order_by('-end_time').first()
                    if latest_scan and latest_scan.result:
                        try:
                            result_data = json.loads(latest_scan.result)
                            results = result_data.get('results', [])
                        except json.JSONDecodeError:
                            logger.warning(f"解析最新扫描结果失败: {latest_scan.id}")
            
            # 如果没有找到任何结果
            if not results:
                return JsonResponse({
                    'code': 404,
                    'msg': '未找到可导出的扫描结果',
                    'data': None
                })
            
            # 生成CSV内容
            csv_content = "主机,端口,协议,服务,版本,横幅信息\n"
            for result in results:
                # 处理可能包含逗号和换行符的字段
                host = str(result.get('host', '')).replace(',', '，')
                port = str(result.get('port', ''))
                protocol = str(result.get('protocol', '')).replace(',', '，')
                service = str(result.get('service', '')).replace(',', '，')
                version = str(result.get('version', '')).replace(',', '，')
                banner = str(result.get('banner', '')).replace(',', '，').replace('\n', ' ')
                
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
            
            # 构建响应数据，确保与前端期望的数据结构一致
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
                'service_distribution': result_data.get('service_distribution', {}),
                # 为了兼容前端代码，添加以下字段
                'open_ports': [item.get('port') for item in result_data.get('results', [])],
                'service_info': {}
            }
            
            # 创建service_info结构，为前端模板使用
            for item in result_data.get('results', []):
                port = item.get('port')
                if port:
                    data['service_info'][str(port)] = {
                        'name': item.get('service', ''),
                        'product': '',
                        'version': item.get('version', ''),
                        'os': ''
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
