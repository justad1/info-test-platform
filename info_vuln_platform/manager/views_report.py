import json
from django.shortcuts import render
from django.views import View
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.core.paginator import Paginator
from django.utils import timezone

from .models_report import ScanReport, VulnerabilityReport
from .decorators import login_required, api_login_required

# 扫描报告页面视图
@method_decorator(login_required, name='dispatch')
class ScanReportView(View):
    """扫描报告页面"""
    def get(self, request):
        return render(request, 'scan_report.html')

# 漏洞报告页面视图
@method_decorator(login_required, name='dispatch')
class VulnerabilityReportView(View):
    """漏洞报告页面"""
    def get(self, request):
        return render(request, 'vulnerability_report.html')

# 扫描报告API视图
@method_decorator(csrf_exempt, name='dispatch')
@method_decorator(api_login_required, name='dispatch')
class ScanReportApiView(View):
    """扫描报告API"""
    
    def get(self, request):
        """获取扫描报告列表"""
        try:
            # 获取查询参数
            page = int(request.GET.get('page', 1))
            limit = int(request.GET.get('limit', 10))
            report_type = request.GET.get('report_type', '')
            title = request.GET.get('title', '')
            target = request.GET.get('target', '')
            
            # 构建查询条件
            filters = {}
            if report_type:
                filters['report_type'] = report_type
            if title:
                filters['title__icontains'] = title
            if target:
                filters['target__icontains'] = target
            
            # 查询数据
            reports = ScanReport.objects.filter(**filters)
            
            # 分页
            paginator = Paginator(reports, limit)
            page_data = paginator.get_page(page)
            
            # 构建响应数据
            data = []
            for report in page_data:
                data.append({
                    'id': report.id,
                    'title': report.title,
                    'report_type': report.report_type,
                    'target': report.target,
                    'scan_time': report.scan_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'create_time': report.create_time.strftime('%Y-%m-%d %H:%M:%S'),
                })
            
            return JsonResponse({
                'code': 0,
                'msg': '',
                'count': reports.count(),
                'data': data
            })
            
        except Exception as e:
            return JsonResponse({
                'code': 500,
                'msg': f'获取扫描报告列表失败：{str(e)}',
                'data': None
            })
    
    def post(self, request):
        """创建扫描报告"""
        try:
            data = json.loads(request.body)
            
            # 检查是否是批量导入请求
            if data.get('action') == 'import_history':
                return self.import_history(request, data)
                
            title = data.get('title')
            report_type = data.get('report_type')
            target = data.get('target')
            content = data.get('content')
            scan_time = data.get('scan_time', timezone.now().strftime('%Y-%m-%d %H:%M:%S'))
            
            # 创建报告
            report = ScanReport.objects.create(
                title=title,
                report_type=report_type,
                target=target,
                content=content,
                scan_time=scan_time
            )
            
            return JsonResponse({
                'code': 0,
                'msg': '创建扫描报告成功',
                'data': {
                    'id': report.id
                }
            })
            
        except Exception as e:
            return JsonResponse({
                'code': 500,
                'msg': f'创建扫描报告失败：{str(e)}',
                'data': None
            })
    
    def import_history(self, request, data):
        """批量导入历史记录到报告"""
        try:
            from .models import Subdomain, PortScan, DirScan, FingerprintScan, VulnScan
            
            imported_count = 0
            report_type = data.get('report_type')
            
            if report_type == 'subdomain':
                # 导入子域名扫描历史
                scans = Subdomain.objects.filter(status='completed')
                for scan in scans:
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
                    
                    ScanReport.objects.create(
                        title=f"子域名扫描报告 - {scan.domain} - {scan.create_time.strftime('%Y-%m-%d %H:%M:%S')}",
                        report_type='subdomain',
                        target=scan.domain,
                        scan_time=scan.create_time,
                        content=json.dumps(content, ensure_ascii=False)
                    )
                    imported_count += 1
                    
            elif report_type == 'portscan':
                # 导入端口扫描历史
                scans = PortScan.objects.filter(status='completed')
                for scan in scans:
                    result_data = json.loads(scan.result) if scan.result else {}
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
                    
                    ScanReport.objects.create(
                        title=f"端口扫描报告 - {scan.target} - {scan.start_time.strftime('%Y-%m-%d %H:%M:%S')}",
                        report_type='portscan',
                        target=scan.target,
                        scan_time=scan.start_time,
                        content=json.dumps(content, ensure_ascii=False)
                    )
                    imported_count += 1
                    
            elif report_type == 'dirscan':
                # 导入目录扫描历史
                scans = DirScan.objects.filter(status='completed')
                for scan in scans:
                    result_data = json.loads(scan.result) if scan.result else {}
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
                    
                    ScanReport.objects.create(
                        title=f"目录扫描报告 - {scan.target} - {scan.start_time.strftime('%Y-%m-%d %H:%M:%S')}",
                        report_type='dirscan',
                        target=scan.target,
                        scan_time=scan.start_time,
                        content=json.dumps(content, ensure_ascii=False)
                    )
                    imported_count += 1
                    
            elif report_type == 'fingerprint':
                # 导入指纹识别历史
                scans = FingerprintScan.objects.filter(status='completed')
                for scan in scans:
                    result_data = json.loads(scan.result) if scan.result else {}
                    content = {
                        'scan_info': {
                            'target': scan.target,
                            'start_time': scan.start_time.strftime('%Y-%m-%d %H:%M:%S'),
                            'end_time': scan.end_time.strftime('%Y-%m-%d %H:%M:%S') if scan.end_time else '',
                            'status': scan.status
                        },
                        'fingerprints': result_data.get('fingerprints', []),
                        'tech_stack': result_data.get('tech_stack', {})
                    }
                    
                    ScanReport.objects.create(
                        title=f"指纹识别报告 - {scan.target} - {scan.start_time.strftime('%Y-%m-%d %H:%M:%S')}",
                        report_type='fingerprint',
                        target=scan.target,
                        scan_time=scan.start_time,
                        content=json.dumps(content, ensure_ascii=False)
                    )
                    imported_count += 1
                    
            elif report_type == 'vulnscan':
                # 导入漏洞扫描历史
                scans = VulnScan.objects.filter(status='completed')
                for scan in scans:
                    result_data = json.loads(scan.result) if scan.result else {}
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
                    
                    ScanReport.objects.create(
                        title=f"漏洞扫描报告 - {scan.target} - {scan.start_time.strftime('%Y-%m-%d %H:%M:%S')}",
                        report_type='vulnscan',
                        target=scan.target,
                        scan_time=scan.start_time,
                        content=json.dumps(content, ensure_ascii=False)
                    )
                    imported_count += 1
            
            return JsonResponse({
                'code': 0,
                'msg': f'成功导入 {imported_count} 条历史记录',
                'data': {
                    'imported_count': imported_count
                }
            })
            
        except Exception as e:
            return JsonResponse({
                'code': 500,
                'msg': f'导入历史记录失败：{str(e)}',
                'data': None
            })

# 漏洞报告API视图
@method_decorator(csrf_exempt, name='dispatch')
@method_decorator(api_login_required, name='dispatch')
class VulnerabilityReportApiView(View):
    """漏洞报告API"""
    
    def get(self, request, report_id=None):
        """获取漏洞报告列表或详情"""
        try:
            # 如果有ID，获取详情
            if report_id:
                report = VulnerabilityReport.objects.get(id=report_id)
                data = {
                    'id': report.id,
                    'title': report.title,
                    'target': report.target,
                    'severity': report.severity,
                    'description': report.description,
                    'solution': report.solution,
                    'poc': report.poc,
                    'create_time': report.create_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'update_time': report.update_time.strftime('%Y-%m-%d %H:%M:%S')
                }
                return JsonResponse({
                    'code': 0,
                    'msg': '',
                    'data': data
                })
            
            # 获取查询参数
            page = int(request.GET.get('page', 1))
            limit = int(request.GET.get('limit', 10))
            title = request.GET.get('title', '')
            target = request.GET.get('target', '')
            severity = request.GET.get('severity', '')
            
            # 构建查询条件
            filters = {}
            if title:
                filters['title__icontains'] = title
            if target:
                filters['target__icontains'] = target
            if severity:
                filters['severity'] = severity
            
            # 查询数据
            reports = VulnerabilityReport.objects.filter(**filters)
            
            # 分页
            paginator = Paginator(reports, limit)
            page_data = paginator.get_page(page)
            
            # 构建响应数据
            data = []
            for report in page_data:
                data.append({
                    'id': report.id,
                    'title': report.title,
                    'target': report.target,
                    'severity': report.severity,
                    'create_time': report.create_time.strftime('%Y-%m-%d %H:%M:%S'),
                })
            
            return JsonResponse({
                'code': 0,
                'msg': '',
                'count': reports.count(),
                'data': data
            })
            
        except VulnerabilityReport.DoesNotExist:
            return JsonResponse({
                'code': 404,
                'msg': '漏洞报告不存在',
                'data': None
            })
        except Exception as e:
            return JsonResponse({
                'code': 500,
                'msg': f'获取漏洞报告失败：{str(e)}',
                'data': None
            })
    
    def post(self, request, report_id=None):
        """创建漏洞报告"""
        try:
            data = json.loads(request.body)
            
            # 检查是否是导入Nuclei历史记录请求
            if data.get('action') == 'import_nuclei_history':
                return self.import_nuclei_history(request)
                
            title = data.get('title')
            target = data.get('target')
            severity = data.get('severity', 'medium')
            description = data.get('description', '')
            solution = data.get('solution', '')
            poc = data.get('poc', '')
            
            # 创建报告
            report = VulnerabilityReport.objects.create(
                title=title,
                target=target,
                severity=severity,
                description=description,
                solution=solution,
                poc=poc
            )
            
            return JsonResponse({
                'code': 0,
                'msg': '创建漏洞报告成功',
                'data': {
                    'id': report.id
                }
            })
            
        except Exception as e:
            return JsonResponse({
                'code': 500,
                'msg': f'创建漏洞报告失败：{str(e)}',
                'data': None
            })
            
    def import_nuclei_history(self, request):
        """导入Nuclei漏洞扫描历史记录到漏洞报告"""
        try:
            from .models_vulnscan import VulnScan
            
            imported_count = 0
            # 获取所有已完成的Nuclei扫描记录
            scans = VulnScan.objects.filter(status='completed')
            
            for scan in scans:
                # 解析扫描结果
                result_data = json.loads(scan.result) if scan.result else {}
                vulnerabilities = result_data.get('vulnerabilities', [])
                
                # 导入每个漏洞
                for vuln in vulnerabilities:
                    if not vuln.get('name'):
                        continue
                        
                    # 检查是否已存在相同的漏洞报告
                    existing = VulnerabilityReport.objects.filter(
                        title=f"{vuln.get('name')} - {scan.target}",
                        target=scan.target,
                        severity=vuln.get('severity', 'medium')
                    ).first()
                    
                    if existing:
                        continue  # 跳过已存在的
                        
                    # 创建漏洞报告
                    VulnerabilityReport.objects.create(
                        title=f"{vuln.get('name')} - {scan.target}",
                        target=scan.target,
                        severity=vuln.get('severity', 'medium'),
                        description=vuln.get('description', ''),
                        solution=vuln.get('solution', ''),
                        poc=vuln.get('curl_command', vuln.get('poc', ''))
                    )
                    imported_count += 1
            
            return JsonResponse({
                'code': 0,
                'msg': f'成功导入{imported_count}条漏洞记录',
                'data': {
                    'count': imported_count
                }
            })
                
        except Exception as e:
            return JsonResponse({
                'code': 500,
                'msg': f'导入Nuclei扫描记录失败：{str(e)}',
                'data': None
            }) 