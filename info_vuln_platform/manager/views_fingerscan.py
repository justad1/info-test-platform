import os
import json
import time
import re
import threading
import subprocess
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from django.views import View
from django.utils import timezone
from django.core.paginator import Paginator
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

from .models import FingerprintScan, UserLog, User
from .decorators import login_required

# 指纹识别页面
class FingerprintScanView(View):
    """指纹识别页面"""
    def get(self, request):
        return render(request, 'fingerprint_scan.html')

# 指纹识别API
class FingerprintScanApiView(View):
    """指纹识别API，提供指纹识别的功能"""
    
    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)
    
    @method_decorator(login_required)
    def get(self, request, scan_id=None):
        """获取指纹识别扫描记录"""
        try:
            if scan_id:
                # 获取单个扫描记录
                scan = FingerprintScan.objects.get(id=scan_id)
                
                # 处理结果字段
                result_data = None
                if scan.result:
                    try:
                        result_data = json.loads(scan.result)
                    except json.JSONDecodeError:
                        # 如果不是JSON格式，则创建一个简单的结果对象
                        result_data = {
                            'raw_output': scan.result,
                            'fingerprints': ['数据格式错误'],
                            'title': '-',
                            'web_server': '-'
                        }
                
                data = {
                    'id': scan.id,
                    'target': scan.target,
                    'status': scan.status,
                    'result': result_data,
                    'start_time': scan.start_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'end_time': scan.end_time.strftime('%Y-%m-%d %H:%M:%S') if scan.end_time else None
                }
                return JsonResponse({'code': 200, 'msg': '获取成功', 'data': data})
            else:
                # 获取扫描记录列表
                page = int(request.GET.get('page', 1))
                limit = int(request.GET.get('limit', 10))
                
                scans = FingerprintScan.objects.all().order_by('-start_time')
                
                # 分页
                paginator = Paginator(scans, limit)
                page_obj = paginator.get_page(page)
                
                data = []
                for scan in page_obj:
                    data.append({
                        'id': scan.id,
                        'target': scan.target,
                        'status': scan.status,
                        'start_time': scan.start_time.strftime('%Y-%m-%d %H:%M:%S'),
                        'end_time': scan.end_time.strftime('%Y-%m-%d %H:%M:%S') if scan.end_time else None
                    })
                
                return JsonResponse({
                    'code': 200,
                    'msg': '获取成功',
                    'count': paginator.count,
                    'data': data
                })
        except FingerprintScan.DoesNotExist:
            return JsonResponse({'code': 404, 'msg': '扫描记录不存在'})
        except Exception as e:
            return JsonResponse({'code': 500, 'msg': f'服务器错误: {str(e)}'})
    
    @method_decorator(login_required)
    def delete(self, request, scan_id):
        """删除指纹识别扫描记录"""
        try:
            scan = FingerprintScan.objects.get(id=scan_id)
            scan.delete()
            
            # 记录日志
            if request.session.get('user_id'):
                try:
                    user = User.objects.get(id=request.session.get('user_id'))
                    UserLog.objects.create(
                        user=user,
                        action='删除指纹识别扫描',
                        ip=request.META.get('REMOTE_ADDR'),
                        details=f'删除了指纹识别扫描记录，ID: {scan_id}, 目标: {scan.target}'
                    )
                except User.DoesNotExist:
                    pass
            
            return JsonResponse({'code': 200, 'msg': '删除成功'})
        except FingerprintScan.DoesNotExist:
            return JsonResponse({'code': 404, 'msg': '扫描记录不存在'})
        except Exception as e:
            return JsonResponse({'code': 500, 'msg': f'服务器错误: {str(e)}'})
    
    @method_decorator(login_required)
    def post(self, request):
        """创建指纹识别扫描任务"""
        try:
            data = json.loads(request.body) if request.body else request.POST
            target = data.get('target')
            
            # 验证目标是否为空
            if not target:
                return JsonResponse({'code': 400, 'msg': '扫描目标不能为空'})
            
            # 创建扫描记录
            scan = FingerprintScan.objects.create(
                target=target,
                status='pending',
                result=None
            )
            
            # 记录日志
            if request.session.get('user_id'):
                try:
                    user = User.objects.get(id=request.session.get('user_id'))
                    UserLog.objects.create(
                        user=user,
                        action='创建指纹识别扫描',
                        ip=request.META.get('REMOTE_ADDR'),
                        details=f'创建了指纹识别扫描任务，目标: {target}'
                    )
                except User.DoesNotExist:
                    pass
            
            # 启动扫描线程
            thread = threading.Thread(target=self.run_scan, args=(scan,))
            thread.daemon = True
            thread.start()
            
            return JsonResponse({'code': 200, 'msg': '扫描任务已创建', 'data': {'id': scan.id}})
        except Exception as e:
            return JsonResponse({'code': 500, 'msg': f'服务器错误: {str(e)}'})
    
    def run_scan(self, scan):
        """运行指纹识别扫描"""
        try:
            # 更新扫描状态为运行中
            scan.status = 'running'
            scan.save()
            
            # 构建命令
            tidefinger_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                         'sectools', 'TideFinger_Go', 'TideFinger_linux_amd64_v3.2.3')
            result_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                     'sectools', 'TideFinger_Go', f'result_{scan.id}.txt')
            
            # 构建命令行参数
            cmd = [
                tidefinger_path,
                '-u', scan.target,
                '-o', result_file
            ]
            
            # 执行命令
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            # 读取结果文件
            result_data = {}
            if os.path.exists(result_file):
                with open(result_file, 'r', encoding='utf-8') as f:
                    result_content = f.read()
                
                # 解析结果
                result_data = self.parse_result(result_content)
                
                # 删除临时文件
                try:
                    os.remove(result_file)
                except:
                    pass
            
            # 更新扫描结果
            scan.result = json.dumps(result_data)
            scan.status = 'completed'
            scan.end_time = timezone.now()
            scan.save()
            
        except Exception as e:
            # 更新扫描状态为失败
            scan.status = 'failed'
            scan.result = json.dumps({'error': str(e)})
            scan.end_time = timezone.now()
            scan.save()
    
    def parse_result(self, result_content):
        """解析TideFinger_Go的输出结果"""
        result = {
            'fingerprints': [],
            'tech_stack': {
                'web_server': [],
                'reverse_proxy': [],
                'programming_language': [],
                'ui_framework': [],
                'javascript_library': [],
                'cms': [],
                'other': []
            },
            'raw_output': result_content
        }
        
        # 解析结果内容
        lines = result_content.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # 检测标题信息
            if 'Title:' in line:
                parts = line.split('Title:', 1)
                if len(parts) == 2:
                    result['title'] = parts[1].strip()
            
            # 检测Web服务器信息
            elif 'WebServer:' in line:
                parts = line.split('WebServer:', 1)
                if len(parts) == 2:
                    result['web_server'] = parts[1].strip()
            
            # 检测指纹信息 - 可能是多种格式
            elif '[+]' in line and ':' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    key = parts[0].replace('[+]', '').strip()
                    value = parts[1].strip()
                    
                    if key == 'WebServer':
                        result['web_server'] = value
                    elif key == 'Title':
                        result['title'] = value
                    elif key == 'Fingerprint':
                        # 添加到指纹列表
                        self._add_fingerprint_to_tech_stack(value, result)
            
            # 检测技术栈信息
            elif any(keyword in line.lower() for keyword in ['nginx', 'apache', 'php', 'jquery', 'layui', 'wordpress', 'cms', 'tls', 'https']):
                # 这可能是一行包含多个技术指纹的信息
                # 尝试提取所有可能的技术指纹
                techs = line.split(',')
                for tech in techs:
                    tech = tech.strip()
                    # 过滤掉状态码
                    if tech and not self._is_status_code(tech):
                        self._add_fingerprint_to_tech_stack(tech, result)
            
            # 其他可能的指纹信息行
            elif any(keyword in line for keyword in ['CMS', 'Framework', 'Server', 'Language', 'Database']):
                self._add_fingerprint_to_tech_stack(line, result)
        
        # 将技术栈信息转换为指纹列表
        self._convert_tech_stack_to_fingerprints(result)
        
        # 如果没有找到任何指纹，添加一个提示
        if not result['fingerprints']:
            result['fingerprints'].append('未识别到指纹')
        
        return result
        
    def _is_status_code(self, text):
        """检测是否为状态码"""
        # 检查是否为常见状态码格式，如[200]或200
        if not isinstance(text, str):
            return False
            
        # 先删除常见的括号和空格
        text = text.strip('[](){} \t\n\r')
        
        # 检查是否为3位数字且首位为1-5
        if text.isdigit() and len(text) == 3 and text[0] in ['1', '2', '3', '4', '5']:
            return True
            
        # 检查是否包含常见的状态码模式，如"HTTP 200"或"Status: 404"
        if 'http' in text.lower() and any(code in text for code in ['200', '301', '302', '404', '500']):
            return True
            
        return False
    
    def _add_fingerprint_to_tech_stack(self, fingerprint, result):
        """将指纹添加到相应的技术栈分类中"""
        fingerprint = fingerprint.strip()
        if not fingerprint or self._is_status_code(fingerprint):
            return
            
        # 尝试提取版本号，如 "Nginx 1.18.0" 或 "PHP/7.4.3"
        name = fingerprint
        version = None
        
        # 常见的版本号模式
        version_patterns = [
            r'([\w.-]+)[/\s](\d+(?:\.\d+)*(?:-[\w.]+)?)',  # Nginx 1.18.0 或 PHP/7.4.3
            r'([\w.-]+)\s+v(\d+(?:\.\d+)*(?:-[\w.]+)?)',    # jQuery v3.5.1
            r'([\w.-]+)\s+version\s+(\d+(?:\.\d+)*(?:-[\w.]+)?)', # 显式版本标记
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, fingerprint, re.IGNORECASE)
            if match:
                name = match.group(1)
                version = match.group(2)
                fingerprint = f"{name} {version}"
                break
            
        # 首先确保指纹列表中不重复
        if fingerprint not in result['fingerprints']:
            result['fingerprints'].append(fingerprint)
        
        # 根据关键字分类
        fp_lower = fingerprint.lower()
        
        # Web服务器
        if any(server in fp_lower for server in ['nginx', 'apache', 'iis', 'tomcat', 'weblogic']):
            if fingerprint not in result['tech_stack']['web_server']:
                result['tech_stack']['web_server'].append(fingerprint)
                
        # 反向代理
        elif any(proxy in fp_lower for proxy in ['nginx', 'haproxy', 'traefik', 'envoy']):
            if fingerprint not in result['tech_stack']['reverse_proxy']:
                result['tech_stack']['reverse_proxy'].append(fingerprint)
                
        # 编程语言
        elif any(lang in fp_lower for lang in ['php', 'asp', 'jsp', 'python', 'ruby', 'node.js', 'java']):
            if fingerprint not in result['tech_stack']['programming_language']:
                result['tech_stack']['programming_language'].append(fingerprint)
                
        # UI框架
        elif any(ui in fp_lower for ui in ['layui', 'bootstrap', 'vue', 'react', 'angular', 'element-ui']):
            if fingerprint not in result['tech_stack']['ui_framework']:
                result['tech_stack']['ui_framework'].append(fingerprint)
                
        # JavaScript库
        elif any(js in fp_lower for js in ['jquery', 'axios', 'lodash', 'moment', 'echarts']):
            if fingerprint not in result['tech_stack']['javascript_library']:
                result['tech_stack']['javascript_library'].append(fingerprint)
                
        # CMS系统
        elif any(cms in fp_lower for cms in ['wordpress', 'drupal', 'joomla', 'magento', 'cms']):
            if fingerprint not in result['tech_stack']['cms']:
                result['tech_stack']['cms'].append(fingerprint)
                
        # 其他
        else:
            if fingerprint not in result['tech_stack']['other']:
                result['tech_stack']['other'].append(fingerprint)
    
    def _convert_tech_stack_to_fingerprints(self, result):
        """将技术栈信息转换为指纹列表，并添加分类标记"""
        # 清空原有指纹列表
        result['fingerprints'] = []
        
        # 添加Web服务器
        for item in result['tech_stack']['web_server']:
            result['fingerprints'].append({'type': 'web_server', 'name': item})
            
        # 添加反向代理
        for item in result['tech_stack']['reverse_proxy']:
            result['fingerprints'].append({'type': 'reverse_proxy', 'name': item})
            
        # 添加编程语言
        for item in result['tech_stack']['programming_language']:
            result['fingerprints'].append({'type': 'programming_language', 'name': item})
            
        # 添加UI框架
        for item in result['tech_stack']['ui_framework']:
            result['fingerprints'].append({'type': 'ui_framework', 'name': item})
            
        # 添加JavaScript库
        for item in result['tech_stack']['javascript_library']:
            result['fingerprints'].append({'type': 'javascript_library', 'name': item})
            
        # 添加CMS系统
        for item in result['tech_stack']['cms']:
            result['fingerprints'].append({'type': 'cms', 'name': item})
            
        # 添加其他
        for item in result['tech_stack']['other']:
            result['fingerprints'].append({'type': 'other', 'name': item})
