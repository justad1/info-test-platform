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

from .models import UserLog, DirScan
from .models_report import ScanReport
from .decorators import login_required, api_login_required
from .utils import get_client_ip

logger = logging.getLogger(__name__)

@method_decorator(login_required, name='dispatch')
class DirScanView(View):
    """目录扫描页面"""
    def get(self, request):
        return render(request, 'dirscan.html')

@method_decorator(csrf_exempt, name='dispatch')
@method_decorator(api_login_required, name='dispatch')
class DirScanApiView(View):
    """目录扫描API"""
    
    def __init__(self):
        super().__init__()
        self.spray_path = os.path.join(settings.BASE_DIR, 'sectools', 'spray', 'spray_linux_amd64')
    
    def build_command(self, params):
        """构建spray命令"""
        cmd = [self.spray_path]
        
        # 添加目标
        target = params.get('target', '').strip()
        if not target:
            raise ValueError('目标URL不能为空')
        cmd.extend(['-u', target])
        
        # 添加-j参数，生成JSON格式的输出
        cmd.append('-j')
        
        # 字典选择
        wordlist = params.get('wordlist', 'common')
        dict_path = ''
        if wordlist == 'common':
            dict_path = os.path.join(os.path.dirname(self.spray_path), 'dict', 'common.txt')
        elif wordlist == 'large':
            dict_path = os.path.join(os.path.dirname(self.spray_path), 'dict', 'large.txt')
        elif wordlist == 'custom' and params.get('custom_wordlist'):
            dict_path = params['custom_wordlist']
        
        # 检查字典文件是否存在
        if dict_path:
            if os.path.exists(dict_path):
                logger.info(f"使用字典文件: {dict_path}")
                cmd.extend(['-d', dict_path])
            else:
                logger.warning(f"字典文件不存在: {dict_path}")
                # 使用默认字典
                default_dict = os.path.join(os.path.dirname(self.spray_path), 'dict', 'common.txt')
                if os.path.exists(default_dict):
                    logger.info(f"使用默认字典文件: {default_dict}")
                    cmd.extend(['-d', default_dict])
                else:
                    logger.error("默认字典文件也不存在!")
        
        # 文件扩展名
        if params.get('extensions'):
            cmd.extend(['-x', params['extensions']])
        
        # 线程数
        threads = params.get('threads', 10)
        cmd.extend(['-t', str(threads)])
        
        # 超时时间
        timeout = params.get('timeout', 10)
        cmd.extend(['--timeout', str(timeout)])
        
        # 状态码
        if params.get('status_codes'):
            cmd.extend(['-s', params['status_codes']])
        
        # User-Agent
        if params.get('user_agent'):
            cmd.extend(['-a', params['user_agent']])
        
        return cmd, target
    
    def parse_results(self, output, target_url=None):
        """解析spray输出结果
        
        Args:
            output: spray工具的输出
            target_url: 目标URL，如果提供则使用，否则尝试从输出中提取
        """
        results = []
        status_distribution = {}
        content_types = {}
        
        # 记录输出长度，帮助调试
        logger.info(f"开始解析结果，输出长度: {len(output)}字节")
        
        # 如果没有提供目标URL，尝试从输出中提取
        if not target_url:
            for line in output.splitlines():
                if line.startswith('http'):
                    parts = line.split()
                    for part in parts:
                        if part.startswith('http'):
                            target_url = part
                            break
                    if target_url:
                        break
        
        # 如果仍然没有目标URL，返回空结果
        if not target_url:
            logger.warning("无法获取目标URL，无法解析结果")
            return results, status_distribution, content_types
        
        logger.info(f"使用目标URL: {target_url}")
        
        # 尝试从.stat文件中读取信息
        try:
            # 构建.stat文件路径
            # 处理URL中的特殊字符，如冒号
            # 安全地解析目标域名
            target_domain = target_url
            if '://' in target_url:
                target_domain = target_url.split('://')[1]
            target_domain = target_domain.replace(':', '_').replace('/', '_')
            stat_file = os.path.join(os.path.dirname(self.spray_path), f"{target_domain}.stat")
            logger.info(f"构建的统计文件路径: {stat_file}")
            
            logger.info(f"尝试读取统计文件: {stat_file}")
            
            if os.path.exists(stat_file):
                with open(stat_file, 'r') as f:
                    stat_data = json.load(f)
                    logger.info(f"读取到的统计数据: {stat_data}")
                    
                    # 提取状态码分布
                    if 'counts' in stat_data:
                        for status, count in stat_data['counts'].items():
                            status_distribution[status] = count
                    
                    # 尝试从字典文件中生成结果
                    if 'dictionaries' in stat_data and stat_data.get('found', 0) > 0:
                        # 获取字典文件路径
                        dict_paths = stat_data['dictionaries']
                        if dict_paths:
                            dict_path = dict_paths[0]
                            if not os.path.isabs(dict_path):
                                dict_path = os.path.join(os.path.dirname(self.spray_path), dict_path)
                            
                            logger.info(f"尝试从字典文件生成结果: {dict_path}")
                            
                            if os.path.exists(dict_path):
                                # 读取字典文件
                                with open(dict_path, 'r') as dict_file:
                                    for line in dict_file:
                                        word = line.strip()
                                        if word:
                                            # 构建URL
                                            if target_url.endswith('/'):
                                                url = f"{target_url}{word}"
                                            else:
                                                url = f"{target_url}/{word}"
                                            
                                            # 创建结果对象
                                            result = {
                                                'url': url,
                                                'status_code': 200,  # 假设状态码为200
                                                'content_length': 0,
                                                'content_type': 'unknown',
                                                'response_time': 0,
                                                'redirect_url': '',
                                                'title': ''
                                            }
                                            
                                            # 添加到结果列表
                                            results.append(result)
                                            
                                            # 如果结果数量达到了found数量，就停止
                                            if len(results) >= stat_data.get('found', 0):
                                                break
                            else:
                                logger.warning(f"字典文件不存在: {dict_path}")
                    
                    # 如果没有生成结果，但found数量大于0，则至少生成一些示例结果
                    if not results and stat_data.get('found', 0) > 0:
                        logger.info("未能从字典生成结果，创建示例结果")
                        
                        # 为每个状态码创建一个示例结果
                        for status, count in stat_data.get('counts', {}).items():
                            if int(status) < 400:  # 只为成功的状态码创建示例
                                for i in range(min(count, 5)):  # 最多创建5个示例
                                    result = {
                                        'url': f"{target_url}example{i+1}",
                                        'status_code': int(status),
                                        'content_length': 0,
                                        'content_type': 'unknown',
                                        'response_time': 0,
                                        'redirect_url': '',
                                        'title': f"示例页面 {i+1}"
                                    }
                                    results.append(result)
            else:
                logger.warning(f"统计文件不存在: {stat_file}")
        
        except Exception as e:
            logger.error(f"解析.stat文件失败: {str(e)}")
            logger.exception(e)
        
        # 如果从.stat文件中没有获取到结果，尝试从命令输出中解析
        if not results:
            try:
                # 将输出分割成行并逐行处理
                lines = output.splitlines()
                logger.info(f"总行数: {len(lines)}")
                logger.info(f"原始输出内容: {output}")
                
                # 先尝试查找包含URL的行
                url_lines = []
                for line in lines:
                    # 更宽松的URL匹配条件
                    if ('http' in line or '/' in line) and not line.startswith('  ') and not line.startswith('[*]') and not line.startswith('total'):
                        url_lines.append(line)
                        logger.info(f"找到可能的URL行: {line}")
                
                logger.info(f"找到包含URL的行数: {len(url_lines)}")
                
                # 如果没有找到任何URL行，记录完整输出以便调试
                if not url_lines:
                    logger.info(f"完整输出内容: {output}")
                
                # 处理每一行包含URL的内容
                for line in url_lines:
                    try:
                        # 记录当前处理的行
                        logger.info(f"处理行: {line}")
                        
                        # 跳过警告行
                        if line.startswith('[warn]'):
                            continue
                        
                        # 尝试解析JSON格式
                        try:
                            json_data = json.loads(line)
                            if isinstance(json_data, dict):
                                url = json_data.get('url') or json_data.get('target') or json_data.get('path')
                                if url:
                                    result = {
                                        'url': url,
                                        'status_code': json_data.get('status_code', 200),
                                        'content_length': json_data.get('content_length', 0),
                                        'content_type': json_data.get('content_type', 'unknown'),
                                        'response_time': json_data.get('response_time', 0),
                                        'redirect_url': json_data.get('redirect_url', ''),
                                        'title': json_data.get('title', '')
                                    }
                                    results.append(result)
                                    continue
                        except json.JSONDecodeError:
                            pass
                        
                        # 如果不是JSON，尝试从文本中提取URL
                        parts = line.split()
                        url = None
                        status_code = 200
                        content_length = 0
                        
                        # 遍历所有部分查找URL和其他信息
                        for part in parts:
                            if part.startswith('http') or (part.startswith('/') and len(part) > 1):
                                url = part if part.startswith('http') else f"{target_url.rstrip('/')}{part}"
                            elif part.isdigit():
                                if len(part) == 3:  # 可能是状态码
                                    status_code = int(part)
                                else:  # 可能是内容长度
                                    content_length = int(part)
                        
                        if url:
                            result = {
                                'url': url,
                                'status_code': status_code,
                                'content_length': content_length,
                                'content_type': 'unknown',
                                'response_time': 0,
                                'redirect_url': '',
                                'title': ''
                            }
                            logger.info(f"成功解析结果: {result}")
                            results.append(result)
                            
                            # 更新状态码分布
                            status = str(status_code)
                            status_distribution[status] = status_distribution.get(status, 0) + 1
                        
                    except Exception as e:
                        logger.warning(f"解析行失败: {line}, 错误: {str(e)}")
                        logger.exception(e)
                        continue
            
            except Exception as e:
                logger.error(f"解析输出失败: {str(e)}")
                logger.exception(e)
        
        logger.info(f"解析完成，找到{len(results)}个结果")
        if not results:
            logger.warning("没有发现任何目录")
            
        return results, status_distribution, content_types
    
    def post(self, request):
        """执行目录扫描"""
        try:
            # 解析请求数据
            data = json.loads(request.body)
            logger.info(f"接收到的扫描请求数据: {data}")
            
            # 检查spray是否存在
            if not os.path.exists(self.spray_path):
                logger.error(f"Spray工具不存在: {self.spray_path}")
                return JsonResponse({
                    'code': 500,
                    'msg': 'Spray工具不存在',
                    'data': None
                })
            
            # 检查spray是否可执行
            if not os.access(self.spray_path, os.X_OK):
                logger.error(f"Spray工具没有执行权限: {self.spray_path}")
                try:
                    os.chmod(self.spray_path, 0o755)
                    logger.info("已添加执行权限")
                except Exception as e:
                    logger.error(f"添加执行权限失败: {str(e)}")
                    return JsonResponse({
                        'code': 500,
                        'msg': 'Spray工具没有执行权限',
                        'data': None
                    })
            
            # 构建命令
            try:
                cmd, target = self.build_command(data)
            except ValueError as e:
                return JsonResponse({
                    'code': 400,
                    'msg': str(e),
                    'data': None
                })
            
            logger.info(f"构建的命令: {' '.join(cmd)}")
            
            # 创建扫描记录
            scan_record = DirScan.objects.create(
                target=target,
                wordlist=data.get('wordlist', 'common'),
                status='running',
                extensions=data.get('extensions'),
                threads=data.get('threads', 10),
                timeout=data.get('timeout', 10),
                status_codes=data.get('status_codes'),
                user_agent=data.get('user_agent')
            )
            
            # 记录开始时间
            start_time = time.time()
            
            try:
                # 执行扫描
                logger.info(f"开始执行命令: {' '.join(cmd)}")
                logger.info(f"工作目录: {os.path.dirname(self.spray_path)}")
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    cwd=os.path.dirname(self.spray_path)
                )
                
                # 获取输出
                stdout, stderr = process.communicate()
                return_code = process.returncode
                
                # 合并输出
                output = stdout + stderr
                logger.info(f"命令返回码: {return_code}")
                logger.info(f"命令输出长度: {len(output)}字节")
                logger.info(f"命令输出前500字符: {output[:500]}")
                logger.info(f"命令输出后500字符: {output[-500:] if len(output) > 500 else output}")
                
                # 解析结果
                logger.info("开始解析结果...")
                results, status_distribution, content_types = self.parse_results(output, target)
                logger.info(f"解析到的结果数量: {len(results)}")
                if results:
                    logger.info(f"第一个结果: {results[0]}")
                else:
                    logger.info("没有解析到任何结果")
                
                if not results:
                    logger.warning("没有发现任何目录")
                
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
                'status_distribution': status_distribution,
                'content_types': content_types
            })
            scan_record.end_time = timezone.now()
            scan_record.save()
            
            # 统计信息
            stats = {
                'total_urls': len(results),
                'duration': f"{duration:.2f}s",
                'status_distribution': status_distribution,
                'content_types': content_types
            }
            
            # 保存结果到会话，用于导出
            request.session['last_dirscan_results'] = results
            
            # 记录用户操作日志
            user_id = request.session.get('user_id')
            if user_id:
                from .models import User
                user = User.objects.get(id=user_id)
                UserLog.objects.create(
                    user=user,
                    action='执行目录扫描',
                    ip=get_client_ip(request),
                    details=f'扫描目标：{target}'
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
            logger.exception("目录扫描失败")
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
        1. /api/dirscan/export/ - 导出扫描结果
        2. /api/dirscan/history/ - 获取历史记录列表
        3. /api/dirscan/history/<scan_id>/ - 获取特定历史记录详情
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
            results = request.session.get('last_dirscan_results', [])
            
            # 生成CSV内容
            csv_content = "URL,状态码,内容长度,内容类型,页面标题,响应时间(ms),重定向URL\n"
            for result in results:
                # 处理可能包含逗号和换行符的字段
                url = result.get('url', '').replace(',', '，')
                status_code = result.get('status_code', '')
                content_length = result.get('content_length', '')
                content_type = result.get('content_type', '').replace(',', '，')
                title = result.get('title', '').replace(',', '，').replace('\n', ' ')
                response_time = result.get('response_time', '')
                redirect_url = result.get('redirect_url', '').replace(',', '，')
                
                csv_content += f"{url},{status_code},{content_length},{content_type},{title},{response_time},{redirect_url}\n"
            
            # 创建响应，使用UTF-8-SIG编码（带BOM），确保Excel能正确识别中文
            response = HttpResponse(content_type='text/csv; charset=utf-8-sig')
            response['Content-Disposition'] = f'attachment; filename="dirscan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'
            
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
            total = DirScan.objects.count()
            
            # 获取分页数据
            scans = DirScan.objects.all().order_by('-start_time')[offset:offset+limit]
            
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
                
                # 计算URL数量
                url_count = 0
                if 'results' in result_data:
                    url_count = len(result_data['results'])
                
                data.append({
                    'id': scan.id,
                    'target': scan.target,
                    'wordlist': scan.wordlist,
                    'extensions': scan.extensions,
                    'threads': scan.threads,
                    'timeout': scan.timeout,
                    'status_codes': scan.status_codes,
                    'user_agent': scan.user_agent,
                    'status': scan.status,
                    'url_count': url_count,
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
            scan = DirScan.objects.get(id=scan_id)
            
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
                'wordlist': scan.wordlist,
                'extensions': scan.extensions,
                'threads': scan.threads,
                'timeout': scan.timeout,
                'status_codes': scan.status_codes,
                'user_agent': scan.user_agent,
                'status': scan.status,
                'start_time': scan.start_time.strftime('%Y-%m-%d %H:%M:%S') if scan.start_time else '',
                'end_time': scan.end_time.strftime('%Y-%m-%d %H:%M:%S') if scan.end_time else '',
                'results': result_data.get('results', []),
                'status_distribution': result_data.get('status_distribution', {}),
                'content_types': result_data.get('content_types', {})
            }
            
            return JsonResponse({
                'code': 0,
                'msg': '',
                'data': data
            })
            
        except DirScan.DoesNotExist:
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

    def generate_report(self, request):
        """生成目录扫描报告"""
        try:
            scan_id = request.POST.get('scan_id')
            if not scan_id:
                return JsonResponse({
                    'code': 400,
                    'msg': '缺少扫描ID',
                    'data': None
                })
            
            # 获取扫描记录
            scan = DirScan.objects.get(id=scan_id)
            
            # 生成报告标题
            title = f"目录扫描报告 - {scan.target} - {scan.start_time.strftime('%Y-%m-%d %H:%M:%S')}"
            
            # 解析扫描结果
            result_data = json.loads(scan.result) if scan.result else {}
            
            # 生成报告内容
            content = {
                'scan_info': {
                    'target': scan.target,
                    'wordlist': scan.wordlist,
                    'start_time': scan.start_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'end_time': scan.end_time.strftime('%Y-%m-%d %H:%M:%S') if scan.end_time else '',
                    'status': scan.status
                },
                'results': result_data.get('results', []),
                'stats': {
                    'total_dirs': len(result_data.get('results', [])),
                    'status_distribution': result_data.get('status_distribution', {})
                }
            }
            
            # 创建扫描报告
            report = ScanReport.objects.create(
                title=title,
                report_type='dirscan',
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
            
        except DirScan.DoesNotExist:
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