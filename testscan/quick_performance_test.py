#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
快速性能测试脚本 - 用于简单测试四种安全工具的性能
"""

import os
import subprocess
import json
import time
import sys
from datetime import datetime

# 工具路径
TOOLS_BASE_DIR = '/root/projects/info-test-platform/info_vuln_platform/sectools'
NAABU_PATH = os.path.join(TOOLS_BASE_DIR, 'naabu/naabu')
SUBFINDER_PATH = os.path.join(TOOLS_BASE_DIR, 'subfinder/subfinder')
TIDEFINGER_PATH = os.path.join(TOOLS_BASE_DIR, 'TideFinger_Go/TideFinger_linux_amd64_v3.2.3')
NUCLEI_PATH = os.path.join(TOOLS_BASE_DIR, 'Nuclei/nuclei')

# 创建日志目录
if not os.path.exists('logs'):
    os.makedirs('logs')

def run_cmd(cmd, timeout=300):
    """执行命令并返回结果"""
    print(f"执行命令: {' '.join(cmd)}")
    
    start_time = time.time()
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        stdout, stderr = process.communicate(timeout=timeout)
        end_time = time.time()
        
        return {
            'success': process.returncode == 0,
            'stdout': stdout,
            'stderr': stderr,
            'execution_time': end_time - start_time
        }
    except subprocess.TimeoutExpired:
        print(f"命令执行超时 ({timeout}秒)")
        return {'success': False, 'execution_time': timeout, 'error': '执行超时'}
    except Exception as e:
        print(f"执行命令时出错: {str(e)}")
        return {'success': False, 'execution_time': time.time() - start_time, 'error': str(e)}

def quick_port_scan(target):
    """快速端口扫描测试"""
    print(f"\n=== 端口扫描测试 ({target}) ===")
    
    # 快速扫描常见端口
    cmd = [
        NAABU_PATH,
        '-host', target,
        '-p', '80,443,8080,8443,22,23,25,3306,3389,6379,1433,1521,3306,5432,5672,6379,11211,15672,27017,27018,5984,6379,11211,15672,27017,27018,5984,6379,11211,15672,27017,27018,5984',  # 常见Web端口
        '-c', '20',                # 高并发
        '-timeout', '3',           # 较短超时
        '-json'
    ]
    
    result = run_cmd(cmd, timeout=120)
    
    if result['success']:
        print(f"端口扫描完成，耗时: {result['execution_time']:.2f}秒")
        
        # 解析结果
        open_ports = []
        for line in result['stdout'].splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                if 'port' in data:
                    open_ports.append(f"{data.get('host', target)}:{data['port']}")
            except:
                continue
        
        if open_ports:
            print(f"发现开放端口: {', '.join(open_ports)}")
        else:
            print("未发现开放端口")
    else:
        print(f"端口扫描失败，耗时: {result['execution_time']:.2f}秒")
        if 'stderr' in result and result['stderr']:
            print(f"错误信息: {result['stderr']}")
    
    return result

def quick_subdomain_scan(target):
    """快速子域名扫描测试"""
    print(f"\n=== 子域名扫描测试 ({target}) ===")
    
    # 提取根域名（针对子域名）
    root_domain = target
    parts = target.split('.')
    if len(parts) > 2 and len(parts[-2]) > 3:  # 简单判断，如果倒数第二部分超过3个字符，可能是主域
        root_domain = '.'.join(parts[-2:])
    
    cmd = [
        SUBFINDER_PATH,
        '-d', root_domain,
        '-t', '20',       # 高并发
        '-timeout', '5',  # 较短超时
        '-json'
    ]
    
    result = run_cmd(cmd, timeout=180)
    
    if result['success']:
        print(f"子域名扫描完成，耗时: {result['execution_time']:.2f}秒")
        
        # 解析结果
        subdomains = []
        for line in result['stdout'].splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                if 'host' in data:
                    subdomains.append(data['host'])
            except:
                continue
        
        if subdomains:
            print(f"发现子域名数量: {len(subdomains)}")
            # 最多显示5个子域名
            if len(subdomains) > 0:
                print(f"部分子域名: {', '.join(subdomains[:5])}")
                if len(subdomains) > 5:
                    print(f"...共 {len(subdomains)} 个")
        else:
            print("未发现子域名")
    else:
        print(f"子域名扫描失败，耗时: {result['execution_time']:.2f}秒")
        if 'stderr' in result and result['stderr']:
            print(f"错误信息: {result['stderr']}")
    
    return result

def quick_fingerprint_scan(target):
    """快速指纹识别测试"""
    print(f"\n=== 指纹识别测试 ({target}) ===")
    
    output_file = f"logs/quick_tidefinger_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    cmd = [
        TIDEFINGER_PATH,
        '-u', target,
        '-o', output_file
    ]
    
    result = run_cmd(cmd, timeout=120)
    
    if result['success']:
        print(f"指纹识别完成，耗时: {result['execution_time']:.2f}秒")
        print(f"结果已保存到 {output_file}")
        
        # 显示原始输出
        if result['stdout']:
            print("指纹识别输出:")
            print(result['stdout'])
    else:
        print(f"指纹识别失败，耗时: {result['execution_time']:.2f}秒")
        if 'stderr' in result and result['stderr']:
            print(f"错误信息: {result['stderr']}")
    
    return result

def quick_vulnerability_scan(target):
    """快速漏洞扫描测试"""
    print(f"\n=== 漏洞扫描测试 ({target}) ===")
    
    cmd = [
        NUCLEI_PATH,
        '-u', target,
        '-t', 'technologies',  # 只使用技术识别模板
        '-c', '20',            # 高并发
        '-timeout', '3',       # 较短超时
        '-rate-limit', '150',  # 限制请求速率
        '-stats',
        '-j'
    ]
    
    result = run_cmd(cmd, timeout=180)
    
    if result['success']:
        print(f"漏洞扫描完成，耗时: {result['execution_time']:.2f}秒")
        
        # 解析结果
        findings = []
        stats = {}
        for line in result['stdout'].splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                if 'template-id' in data:
                    findings.append(data)
                elif 'stats' in data:
                    stats = data['stats']
            except:
                continue
        
        if findings:
            print(f"发现结果数量: {len(findings)}")
            # 最多显示3个发现
            if len(findings) > 0:
                for i, finding in enumerate(findings[:3]):
                    template_id = finding.get('template-id', 'Unknown')
                    severity = finding.get('info', {}).get('severity', 'Unknown')
                    name = finding.get('info', {}).get('name', 'Unknown')
                    print(f"发现 {i+1}: {name} ({template_id}) - 严重性: {severity}")
                if len(findings) > 3:
                    print(f"...共 {len(findings)} 个发现")
        else:
            print("未发现漏洞")
            
        # 显示统计信息
        if stats:
            requests = stats.get('requests', 0)
            duration = result['execution_time']
            if duration > 0:
                print(f"扫描速率: {requests/duration:.2f} 请求/秒")
    else:
        print(f"漏洞扫描失败，耗时: {result['execution_time']:.2f}秒")
        if 'stderr' in result and result['stderr']:
            print(f"错误信息: {result['stderr']}")
    
    return result

def run_all_tests(target):
    """运行所有快速测试"""
    print(f"开始对 {target} 进行快速性能测试...")
    
    # 确保工具有执行权限
    for tool_path in [NAABU_PATH, SUBFINDER_PATH, TIDEFINGER_PATH, NUCLEI_PATH]:
        if os.path.exists(tool_path) and not os.access(tool_path, os.X_OK):
            try:
                os.chmod(tool_path, 0o755)
                print(f"已为 {os.path.basename(tool_path)} 添加执行权限")
            except Exception as e:
                print(f"无法为 {os.path.basename(tool_path)} 添加执行权限: {str(e)}")
    
    start_time = time.time()
    
    # 运行测试
    port_result = quick_port_scan(target)
    subdomain_result = quick_subdomain_scan(target)
    fingerprint_result = quick_fingerprint_scan(target)
    vulnerability_result = quick_vulnerability_scan(target)
    
    end_time = time.time()
    total_time = end_time - start_time
    
    # 总结
    print("\n" + "="*50)
    print(f"测试完成，总耗时: {total_time:.2f}秒")
    print("性能摘要:")
    print(f"端口扫描: {'成功' if port_result['success'] else '失败'}, 耗时: {port_result['execution_time']:.2f}秒")
    print(f"子域名扫描: {'成功' if subdomain_result['success'] else '失败'}, 耗时: {subdomain_result['execution_time']:.2f}秒")
    print(f"指纹识别: {'成功' if fingerprint_result['success'] else '失败'}, 耗时: {fingerprint_result['execution_time']:.2f}秒")
    print(f"漏洞扫描: {'成功' if vulnerability_result['success'] else '失败'}, 耗时: {vulnerability_result['execution_time']:.2f}秒")
    print("="*50)
    
    # 保存结果
    results = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "total_execution_time": total_time,
        "port_scan": {
            "success": port_result['success'],
            "execution_time": port_result['execution_time']
        },
        "subdomain_scan": {
            "success": subdomain_result['success'],
            "execution_time": subdomain_result['execution_time']
        },
        "fingerprint_scan": {
            "success": fingerprint_result['success'],
            "execution_time": fingerprint_result['execution_time']
        },
        "vulnerability_scan": {
            "success": vulnerability_result['success'],
            "execution_time": vulnerability_result['execution_time']
        }
    }
    
    results_file = f"logs/quick_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"测试结果已保存到 {results_file}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("使用方法: python quick_performance_test.py <目标域名或IP>")
        sys.exit(1)
    
    target = sys.argv[1]
    run_all_tests(target) 