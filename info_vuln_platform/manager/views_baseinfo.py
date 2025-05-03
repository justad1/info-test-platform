import json
import socket
import logging
import whois
import requests
from django.shortcuts import render
from django.views import View
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

from .models import BaseInfoQuery, UserLog
from .decorators import login_required

# 获取客户端IP
def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

# 基础信息页面视图
@method_decorator(login_required, name='dispatch')
class BaseInfoView(View):
    """基础信息查询页面"""
    def get(self, request):
        return render(request, 'baseinfo.html')

# 基础信息API
@method_decorator(csrf_exempt, name='dispatch')
@method_decorator(login_required, name='dispatch')
class BaseInfoApiView(View):
    """基础信息API"""
    
    # 检测域名是否为CDN，返回域名对应的IP列表
    def get_cdn(self, domain):
        ip_list = set()
        try:
            addrs = socket.getaddrinfo(domain, 'http')
            for item in addrs:
                ip = item[4][0]
                ip_list.add(ip)
        except socket.gaierror as e:
            logging.error(f'Socket error: {e}')
            logging.error(f'域名解析失败: {domain}')
        except Exception as e:
            logging.error(f'未知错误: {e}')   
        
        has_cdn = len(ip_list) > 1
        return has_cdn, list(ip_list)
    
    # 获取whois信息
    def get_whois(self, domain):
        try:
            whois_info = whois.whois(domain)
            return json.dumps(whois_info, default=str)
        except Exception as e:
            logging.error(f'WHOIS查询失败：{e}')
            return None
    
    # 获取icp备案信息
    def get_icp(self, domain):
        params = {
            "domainName": domain,   # 查询的域名
            "key":  'c2bc810f80a45c11cfaf46fe357e5b4f'       # 类型参数
        }
        try:
            # 发送GET请求
            response = requests.get(url="http://v.juhe.cn/siteTools/app/NewDomain/query", params=params)
            
            # 检查HTTP状态码
            if response.status_code == 200:
                return response.text
            else:
                logging.error(f"ICP查询请求失败，状态码：{response.status_code}")
                logging.error(f"错误信息：{response.text}")
                return None
        except requests.exceptions.RequestException as e:
            logging.error(f"ICP查询网络请求异常：{e}")
            return None
    
    # 获取基础信息查询历史
    def get(self, request):
        """获取基础信息查询历史"""
        try:
            # 获取查询参数
            page = int(request.GET.get('page', 1))
            limit = int(request.GET.get('limit', 10))
            domain = request.GET.get('domain', '')
            
            # 查询数据库
            query = BaseInfoQuery.objects.all()
            
            # 如果提供了域名，进行筛选
            if domain:
                query = query.filter(domain__icontains=domain)
            
            # 计算总数
            count = query.count()
            
            # 分页
            start = (page - 1) * limit
            end = page * limit
            query_list = query[start:end]
            
            # 构造返回数据
            data = []
            for item in query_list:
                data.append({
                    'id': item.id,
                    'domain': item.domain,
                    'has_cdn': item.has_cdn,
                    'ip_list': item.ip_list,
                    'whois_info': item.whois_info,
                    'icp_info': item.icp_info,
                    'query_time': item.query_time.strftime('%Y-%m-%d %H:%M:%S')
                })
            
            return JsonResponse({
                'code': 0,
                'msg': '获取成功',
                'count': count,
                'data': data
            })
        except Exception as e:
            logging.error(f"获取基础信息查询历史失败：{e}")
            return JsonResponse({
                'code': 500,
                'msg': f'获取失败：{str(e)}',
                'data': []
            })
    
    # 执行基础信息查询
    def post(self, request):
        """执行基础信息查询"""
        try:
            # 解析请求数据
            data = json.loads(request.body)
            domain = data.get('domain', '')
            
            # 验证域名
            if not domain:
                return JsonResponse({
                    'code': 400,
                    'msg': '请提供有效的域名',
                    'data': None
                })
            
            # 执行查询
            has_cdn, ip_list = self.get_cdn(domain)
            whois_info = self.get_whois(domain)
            icp_info = self.get_icp(domain)
            
            # 保存查询结果
            query = BaseInfoQuery.objects.create(
                domain=domain,
                has_cdn=has_cdn,
                ip_list=json.dumps(ip_list),
                whois_info=whois_info,
                icp_info=icp_info
            )
            
            # 记录用户操作日志
            user_id = request.session.get('user_id')
            if user_id:
                from .models import User
                user = User.objects.get(id=user_id)
                UserLog.objects.create(
                    user=user,
                    action='执行基础信息查询',
                    ip=get_client_ip(request),
                    details=f'查询域名：{domain}'
                )
            
            # 构造返回数据
            return JsonResponse({
                'code': 0,
                'msg': '查询成功',
                'data': {
                    'id': query.id,
                    'domain': query.domain,
                    'has_cdn': query.has_cdn,
                    'ip_list': ip_list,
                    'whois_info': json.loads(whois_info) if whois_info else None,
                    'icp_info': json.loads(icp_info) if icp_info else None,
                    'query_time': query.query_time.strftime('%Y-%m-%d %H:%M:%S')
                }
            })
        except Exception as e:
            logging.error(f"执行基础信息查询失败：{e}")
            return JsonResponse({
                'code': 500,
                'msg': f'查询失败：{str(e)}',
                'data': None
            })
