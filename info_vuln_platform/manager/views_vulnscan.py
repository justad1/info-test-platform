import json
import os
import subprocess
import time
import logging
import tempfile
from django.shortcuts import render
from django.views import View
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from datetime import datetime

from .models import UserLog
from .models_vulnscan import VulnScan
from .models_report import ScanReport, VulnerabilityReport
from .decorators import login_required, api_login_required
from .utils import get_client_ip

logger = logging.getLogger(__name__)

# 漏洞扫描页面视图
@method_decorator(login_required, name='dispatch')
class VulnScanView(View):
    """漏洞扫描页面"""
    def get(self, request):
        return render(request, 'vulnscan.html')

# 漏洞扫描API
@method_decorator(csrf_exempt, name='dispatch')
@method_decorator(api_login_required, name='dispatch')
class VulnScanApiView(View):
    """漏洞扫描API"""
    
    def __init__(self):
        super().__init__()
        self.nuclei_path = os.path.join(settings.BASE_DIR, 'sectools', 'Nuclei', 'nuclei')
        # 如果路径不存在，尝试使用绝对路径
        if not os.path.exists(self.nuclei_path):
            self.nuclei_path = '/root/project/info-test-platform/info_vuln_platform/sectools/Nuclei/nuclei'
            logger.info(f"使用绝对路径: {self.nuclei_path}")
    
    def build_command(self, params):
        """构建nuclei命令"""
        cmd = [self.nuclei_path]
        
        # 添加目标
        if params.get('target'):
            cmd.extend(['-u', params['target']])
        
        # 添加模板
        if params.get('templates'):
            templates = params['templates']
            if templates == 'all':
                # 使用所有模板
                cmd.append('-as')  # 扫描所有模板
            elif templates == 'cve':
                # 使用CVE模板
                cmd.extend(['-t', 'cves'])
            elif templates == 'vulnerabilities':
                # 使用漏洞模板
                cmd.extend(['-t', 'vulnerabilities'])
            elif templates == 'technologies':
                # 使用技术识别模板
                cmd.extend(['-t', 'technologies'])
            elif templates == 'exposures':
                # 使用敏感信息泄露模板
                cmd.extend(['-t', 'exposures'])
            elif templates == 'misconfiguration':
                # 使用错误配置模板
                cmd.extend(['-t', 'misconfiguration'])
            elif templates == 'custom' and params.get('custom_templates'):
                # 使用自定义模板
                cmd.extend(['-t', params['custom_templates']])
        
        # 添加严重级别过滤
        if params.get('severity'):
            severity = params['severity']
            if severity != 'all':
                cmd.extend(['-s', severity])
        
        # 添加线程数
        if params.get('threads'):
            cmd.extend(['-c', str(params['threads'])])
        
        # 添加超时时间（分钟）
        if params.get('timeout'):
            cmd.extend(['-timeout', str(params['timeout'])])
        
        # 添加输出格式为JSON
        cmd.append('-j')  # 使用-j参数输出JSON格式结果
        
        # 添加其他有用的参数
        cmd.extend(['-stats', '-silent'])  # 显示统计信息，减少不必要的输出
        
        logger.info(f"构建的Nuclei命令: {' '.join(cmd)}")
        return cmd
    
    def parse_results(self, output):
        """解析nuclei输出结果"""
        results = []
        severity_distribution = {
            'info': 0,
            'low': 0,
            'medium': 0,
            'high': 0,
            'critical': 0
        }
        
        logger.info(f"开始解析Nuclei输出结果，输出长度: {len(output)}")
        
        # 如果输出为空，直接返回空结果
        if not output.strip():
            logger.warning("没有收到Nuclei输出结果")
            return results, severity_distribution
        
        for line in output.splitlines():
            if not line.strip():
                continue
            
            # 跳过非JSON行（如标志行和日志行）
            if line.startswith('[') and not line.startswith('[{'):
                continue
                
            try:
                # 解析JSON输出
                result = json.loads(line)
                
                # 检查是否是统计信息行
                if 'duration' in result and 'templates' in result and 'matched' in result:
                    # 处理percent字段的异常值
                    if 'percent' in result and isinstance(result['percent'], (int, float)) and result['percent'] > 100:
                        logger.warning(f"检测到percent字段异常值: {result['percent']}，已忽略")
                        result['percent'] = 0
                    logger.info(f"检测到统计信息: {result}")
                    continue
                
                # 检查是否是结果行（而不是统计信息行）
                if not ('template-id' in result or 'matcher-name' in result):
                    logger.warning(f"跳过非结果行: {result}")
                    continue
                
                # 提取关键信息
                info = {
                    'template': result.get('template', ''),
                    'template_id': result.get('template-id', ''),
                    'name': result.get('info', {}).get('name', ''),
                    'severity': result.get('info', {}).get('severity', '').lower(),
                    'type': result.get('type', ''),
                    'host': result.get('host', ''),
                    'matched': result.get('matched-at', result.get('matched', '')),
                    'timestamp': result.get('timestamp', ''),
                    'matcher_name': result.get('matcher-name', ''),
                    'description': result.get('info', {}).get('description', ''),
                    'reference': result.get('info', {}).get('reference', []),
                    'extracted_results': result.get('extracted-results', []),
                    'curl_command': result.get('curl-command', '')
                }
                
                # 确保所有必要字段都存在
                if not info['template_id']:
                    logger.warning(f"跳过缺少template-id的结果: {result}")
                    continue
                
                # 如果没有name，使用template-id作为名称
                if not info['name']:
                    info['name'] = info['template_id']
                
                # 如果没有严重级别，默认为info
                if not info['severity']:
                    info['severity'] = 'info'
                
                results.append(info)
                
                # 更新严重级别分布
                severity = info['severity'].lower()
                if severity in severity_distribution:
                    severity_distribution[severity] += 1
                else:
                    logger.warning(f"未知的严重级别: {severity}")
                
            except json.JSONDecodeError:
                # 如果不是JSON格式，可能是一个漏洞发现的文本行
                if '] [http] [' in line:
                    parts = line.split('] [http] [')
                    if len(parts) >= 2:
                        template_id = parts[0].strip('[').strip()
                        severity = parts[1].strip(']').strip()
                        url = parts[-1].strip()
                        info = {
                            'template': '',
                            'template_id': template_id,
                            'name': template_id,
                            'severity': severity.lower(),
                            'type': 'http',
                            'host': url,
                            'matched': url,
                            'timestamp': timezone.now().isoformat(),
                            'matcher_name': '',
                            'description': f'使用{template_id}检测到漏洞',
                            'reference': [],
                            'extracted_results': [],
                            'curl_command': ''
                        }
                        results.append(info)
                        
                        # 更新严重级别分布
                        severity = info['severity'].lower()
                        if severity in severity_distribution:
                            severity_distribution[severity] += 1
                        
                        logger.info(f"解析到非JSON格式的漏洞发现: {line}")
                        continue
                logger.warning(f"无法解析JSON行: {line}")
                continue
            except Exception as e:
                logger.error(f"解析结果时出错: {str(e)}")
                continue
        
        logger.info(f"解析完成，发现{len(results)}个结果，严重级别分布: {severity_distribution}")
        return results, severity_distribution
    
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
            scan = VulnScan.objects.get(id=scan_id)
            
            # 生成报告标题
            title = f"漏洞扫描报告 - {scan.target} - {scan.start_time.strftime('%Y-%m-%d %H:%M:%S')}"
            
            # 解析扫描结果
            result_data = json.loads(scan.result) if scan.result else {}
            
            # 生成报告内容
            content = {
                'scan_info': {
                    'target': scan.target,
                    'start_time': scan.start_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'end_time': scan.end_time.strftime('%Y-%m-%d %H:%M:%S') if scan.end_time else '',
                    'status': scan.status,
                    'templates': scan.templates,
                    'severity': scan.severity,
                    'found_count': scan.found_count
                },
                'vulnerabilities': result_data.get('vulnerabilities', [])
            }
            
            # 创建扫描报告
            report = ScanReport.objects.create(
                title=title,
                report_type='vulnscan',
                target=scan.target,
                scan_time=scan.start_time,
                content=json.dumps(content, ensure_ascii=False)
            )
            
            # 如果发现漏洞，同时创建漏洞报告
            vulnerabilities = result_data.get('vulnerabilities', [])
            for vuln in vulnerabilities:
                VulnerabilityReport.objects.create(
                    title=f"{vuln.get('name', '未知漏洞')} - {scan.target}",
                    target=scan.target,
                    severity=vuln.get('severity', 'medium'),
                    description=vuln.get('description', ''),
                    solution=vuln.get('solution', ''),
                    poc=vuln.get('poc', '')
                )
            
            return JsonResponse({
                'code': 0,
                'msg': '生成报告成功',
                'data': {
                    'report_id': report.id
                }
            })
            
        except VulnScan.DoesNotExist:
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
        """处理POST请求"""
        action = request.POST.get('action')
        
        if action == 'generate_report':
            return self.generate_report(request)
        
        try:
            # 解析请求数据
            data = json.loads(request.body)
            logger.info(f"接收到的扫描请求数据: {data}")
            
            # 检查nuclei是否存在
            if not os.path.exists(self.nuclei_path):
                logger.error(f"Nuclei工具不存在: {self.nuclei_path}")
                return JsonResponse({
                    'code': 500,
                    'msg': 'Nuclei工具不存在',
                    'data': None
                })
            
            # 检查nuclei是否可执行
            if not os.access(self.nuclei_path, os.X_OK):
                logger.error(f"Nuclei工具没有执行权限: {self.nuclei_path}")
                try:
                    os.chmod(self.nuclei_path, 0o755)
                    logger.info("已添加执行权限")
                except Exception as e:
                    logger.error(f"添加执行权限失败: {str(e)}")
                    return JsonResponse({
                        'code': 500,
                        'msg': 'Nuclei工具没有执行权限',
                        'data': None
                    })
            
            # 构建命令
            cmd = self.build_command(data)
            logger.info(f"构建的命令: {' '.join(cmd)}")
            
            if not data.get('target'):
                return JsonResponse({
                    'code': 400,
                    'msg': '请输入有效的目标',
                    'data': None
                })
            
            # 创建扫描记录
            scan_record = VulnScan.objects.create(
                target=data.get('target'),
                templates=data.get('templates', 'all'),
                severity=data.get('severity', 'all'),
                threads=data.get('threads', 10),
                timeout=data.get('timeout', 5),
                status='running'
            )
            
            # 记录开始时间
            start_time = time.time()
            
            try:
                # 创建临时文件用于存储输出
                with tempfile.NamedTemporaryFile(delete=False, mode='w+t') as output_file:
                    # 执行扫描
                    logger.info(f"开始执行命令，工作目录: {os.path.dirname(self.nuclei_path)}")
                    process = subprocess.Popen(
                        cmd,
                        stdout=output_file,
                        stderr=subprocess.PIPE,
                        universal_newlines=True,
                        cwd=os.path.dirname(self.nuclei_path)  # 设置工作目录为nuclei所在目录
                    )
                    
                    # 设置超时时间（分钟）
                    # 确保timeout是整数类型
                    timeout_value = data.get('timeout', 5)
                    if isinstance(timeout_value, str):
                        try:
                            timeout_value = int(timeout_value)
                        except ValueError:
                            timeout_value = 5  # 默认值
                    timeout_seconds = timeout_value * 60
                    
                    try:
                        # 等待进程完成，带有超时
                        process.wait(timeout=timeout_seconds)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        logger.warning(f"命令执行超时，已终止: {' '.join(cmd)}")
                        scan_record.status = 'failed'
                        scan_record.save()
                        return JsonResponse({
                            'code': 500,
                            'msg': '扫描超时，已终止',
                            'data': None
                        })
                    
                    # 获取stderr输出
                    stderr = process.stderr.read()
                    return_code = process.returncode
                    
                    # 读取输出文件内容
                    output_file.seek(0)
                    stdout = output_file.read()
                    
                    # 删除临时文件
                    output_file.close()
                    os.unlink(output_file.name)
                    
                    # 合并输出
                    output = stdout
                    
                    logger.info(f"命令返回码: {return_code}")
                    if stderr:
                        logger.warning(f"命令错误输出: {stderr}")
                    
                    # 解析结果
                    results, severity_distribution = self.parse_results(output)
                    logger.info(f"解析到的结果数量: {len(results)}")
                    
                    if not results:
                        logger.warning("没有扫描到漏洞")
                
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
                'severity_distribution': severity_distribution
            })
            scan_record.end_time = timezone.now()
            scan_record.found_count = len(results)
            scan_record.save()
            
            # 统计信息
            stats = {
                'vuln_count': len(results),
                'duration': f"{duration:.2f}s",
                'severity_distribution': severity_distribution,
                'scan_id': scan_record.id
            }
            
            # 将结果按严重级别排序（从高到低）
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
            results.sort(key=lambda x: severity_order.get(x['severity'].lower(), 999))
            
            # 保存结果到会话，用于导出
            request.session['last_vulnscan_results'] = results
            
            # 记录用户操作日志
            user_id = request.session.get('user_id')
            if user_id:
                from .models import User
                try:
                    user = User.objects.get(id=user_id)
                    UserLog.objects.create(
                        user=user,
                        action='执行漏洞扫描',
                        ip=get_client_ip(request),
                        details=f'扫描目标：{data.get("target")}'
                    )
                except User.DoesNotExist:
                    logger.warning(f"用户不存在: {user_id}")
            
            return JsonResponse({
                'code': 0,
                'msg': '扫描完成',
                'data': {
                    'results': results,
                    'stats': stats
                }
            })
        
        except Exception as e:
            logger.exception("漏洞扫描失败")
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
        1. /api/vulnscan/export/ - 导出扫描结果
        2. /api/vulnscan/history/ - 获取历史记录列表
        3. /api/vulnscan/history/<scan_id>/ - 获取特定历史记录详情
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
            results = request.session.get('last_vulnscan_results', [])
            
            # 生成CSV内容
            csv_content = "漏洞名称,严重级别,目标,类型,模板ID,描述,参考链接\n"
            for result in results:
                # 处理参考链接，将列表转换为字符串
                references = "; ".join(result.get('reference', []))
                # 处理描述中的逗号和换行符
                description = result.get('description', '').replace(',', '，').replace('\n', ' ')
                # 处理其他字段，确保所有字段都能正确处理中文
                name = result.get('name', '').replace(',', '，')
                severity = result.get('severity', '').replace(',', '，')
                host = result.get('host', '').replace(',', '，')
                type_ = result.get('type', '').replace(',', '，')
                template_id = result.get('template_id', '').replace(',', '，')
                
                csv_content += f"{name},{severity},{host},{type_},{template_id},{description},{references}\n"
            
            # 创建响应，使用UTF-8-SIG编码（带BOM），确保Excel能正确识别中文
            response = HttpResponse(content_type='text/csv; charset=utf-8-sig')
            response['Content-Disposition'] = f'attachment; filename="vulnscan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'
            
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
            total = VulnScan.objects.count()
            
            # 获取分页数据
            scans = VulnScan.objects.all().order_by('-start_time')[offset:offset+limit]
            
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
                
                # 获取漏洞数量
                vuln_count = scan.found_count
                
                data.append({
                    'id': scan.id,
                    'target': scan.target,
                    'templates': scan.templates,
                    'severity': scan.severity,
                    'status': scan.status,
                    'vuln_count': vuln_count,
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
            scan = VulnScan.objects.get(id=scan_id)
            
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
                'templates': scan.templates,
                'severity': scan.severity,
                'status': scan.status,
                'start_time': scan.start_time.strftime('%Y-%m-%d %H:%M:%S') if scan.start_time else '',
                'end_time': scan.end_time.strftime('%Y-%m-%d %H:%M:%S') if scan.end_time else '',
                'results': result_data.get('results', []),
                'severity_distribution': result_data.get('severity_distribution', {})
            }
            
            return JsonResponse({
                'code': 0,
                'msg': '',
                'data': data
            })
            
        except VulnScan.DoesNotExist:
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
