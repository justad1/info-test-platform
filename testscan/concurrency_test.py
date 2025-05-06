#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
并发性能对比测试脚本 - 用于测试不同并发设置下安全工具的性能表现
"""

import os
import subprocess
import json
import time
import sys
import argparse
import matplotlib.pyplot as plt
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

# 创建图表目录
if not os.path.exists('reports'):
    os.makedirs('reports')

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

def test_port_scan_concurrency(target, concurrency_levels, timeout=60):
    """测试不同并发级别下的端口扫描性能"""
    print(f"\n=== 端口扫描并发测试 ({target}) ===")
    
    results = []
    for concurrency in concurrency_levels:
        print(f"\n测试并发级别: {concurrency}")
        
        # 构建命令
        cmd = [
            NAABU_PATH,
            '-host', target,
            '-p', 'top-100',    # 扫描前100个常用端口
            '-c', str(concurrency),
            '-timeout', '3',
            '-json'
        ]
        
        result = run_cmd(cmd, timeout=timeout)
        
        if result['success']:
            # 计算发现的开放端口数
            open_ports = []
            for line in result['stdout'].splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    if 'port' in data:
                        open_ports.append(data['port'])
                except:
                    continue
            
            print(f"并发级别 {concurrency} 测试完成，耗时: {result['execution_time']:.2f}秒，发现 {len(open_ports)} 个开放端口")
            results.append({
                'concurrency': concurrency,
                'execution_time': result['execution_time'],
                'open_ports_count': len(open_ports),
                'success': True
            })
        else:
            print(f"并发级别 {concurrency} 测试失败，耗时: {result['execution_time']:.2f}秒")
            results.append({
                'concurrency': concurrency,
                'execution_time': result['execution_time'],
                'open_ports_count': 0,
                'success': False
            })
    
    return results

def test_subdomain_scan_concurrency(target, concurrency_levels, timeout=120):
    """测试不同并发级别下的子域名扫描性能"""
    print(f"\n=== 子域名扫描并发测试 ({target}) ===")
    
    # 提取根域名（针对子域名）
    root_domain = target
    parts = target.split('.')
    if len(parts) > 2 and len(parts[-2]) > 3:  # 简单判断，如果倒数第二部分超过3个字符，可能是主域
        root_domain = '.'.join(parts[-2:])
    
    results = []
    for concurrency in concurrency_levels:
        print(f"\n测试并发级别: {concurrency}")
        
        # 构建命令
        cmd = [
            SUBFINDER_PATH,
            '-d', root_domain,
            '-t', str(concurrency),
            '-timeout', '5',
            '-json'
        ]
        
        result = run_cmd(cmd, timeout=timeout)
        
        if result['success']:
            # 计算发现的子域名数
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
            
            print(f"并发级别 {concurrency} 测试完成，耗时: {result['execution_time']:.2f}秒，发现 {len(subdomains)} 个子域名")
            results.append({
                'concurrency': concurrency,
                'execution_time': result['execution_time'],
                'subdomains_count': len(subdomains),
                'success': True
            })
        else:
            print(f"并发级别 {concurrency} 测试失败，耗时: {result['execution_time']:.2f}秒")
            results.append({
                'concurrency': concurrency,
                'execution_time': result['execution_time'],
                'subdomains_count': 0,
                'success': False
            })
    
    return results

def test_vulnerability_scan_concurrency(target, concurrency_levels, timeout=180):
    """测试不同并发级别下的漏洞扫描性能"""
    print(f"\n=== 漏洞扫描并发测试 ({target}) ===")
    
    results = []
    for concurrency in concurrency_levels:
        print(f"\n测试并发级别: {concurrency}")
        
        # 构建命令
        cmd = [
            NUCLEI_PATH,
            '-u', target,
            '-t', 'technologies',
            '-c', str(concurrency),
            '-timeout', '5',
            '-stats',
            '-j'
        ]
        
        result = run_cmd(cmd, timeout=timeout)
        
        if result['success']:
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
            
            requests = stats.get('requests', 0)
            requests_per_second = requests / result['execution_time'] if result['execution_time'] > 0 else 0
            
            print(f"并发级别 {concurrency} 测试完成，耗时: {result['execution_time']:.2f}秒，发现 {len(findings)} 个结果")
            print(f"请求速率: {requests_per_second:.2f} 请求/秒")
            
            results.append({
                'concurrency': concurrency,
                'execution_time': result['execution_time'],
                'findings_count': len(findings),
                'requests': requests,
                'requests_per_second': requests_per_second,
                'success': True
            })
        else:
            print(f"并发级别 {concurrency} 测试失败，耗时: {result['execution_time']:.2f}秒")
            results.append({
                'concurrency': concurrency,
                'execution_time': result['execution_time'],
                'findings_count': 0,
                'requests': 0,
                'requests_per_second': 0,
                'success': False
            })
    
    return results

def generate_concurrency_charts(results, tool_name, target, timestamp):
    """生成并发性能对比图表"""
    try:
        plt.figure(figsize=(12, 8))
        
        # 提取数据
        concurrency_levels = [r['concurrency'] for r in results if r['success']]
        execution_times = [r['execution_time'] for r in results if r['success']]
        
        if not concurrency_levels or not execution_times:
            print(f"没有足够的数据生成 {tool_name} 的性能图表")
            return None
        
        # 执行时间曲线
        plt.subplot(2, 1, 1)
        plt.plot(concurrency_levels, execution_times, 'o-', linewidth=2, markersize=8)
        plt.title(f'{tool_name} 执行时间 vs 并发级别 ({target})', fontsize=14)
        plt.xlabel('并发级别', fontsize=12)
        plt.ylabel('执行时间 (秒)', fontsize=12)
        plt.grid(True)
        
        # 特定指标曲线
        plt.subplot(2, 1, 2)
        
        if tool_name == "端口扫描":
            # 绘制每秒扫描端口数
            ports_per_second = []
            for r in results:
                if r['success']:
                    # 假设扫描了top-100端口
                    ports_per_second.append(100 / r['execution_time'] if r['execution_time'] > 0 else 0)
            
            plt.plot(concurrency_levels, ports_per_second, 'o-', linewidth=2, color='green', markersize=8)
            plt.title(f'{tool_name} 扫描速率 vs 并发级别 ({target})', fontsize=14)
            plt.xlabel('并发级别', fontsize=12)
            plt.ylabel('扫描速率 (端口/秒)', fontsize=12)
            
        elif tool_name == "子域名扫描":
            # 绘制发现的子域名数量
            subdomains_counts = [r['subdomains_count'] for r in results if r['success']]
            plt.plot(concurrency_levels, subdomains_counts, 'o-', linewidth=2, color='orange', markersize=8)
            plt.title(f'{tool_name} 发现子域名数量 vs 并发级别 ({target})', fontsize=14)
            plt.xlabel('并发级别', fontsize=12)
            plt.ylabel('子域名数量', fontsize=12)
            
        elif tool_name == "漏洞扫描":
            # 绘制每秒请求数
            requests_per_second = [r['requests_per_second'] for r in results if r['success']]
            plt.plot(concurrency_levels, requests_per_second, 'o-', linewidth=2, color='red', markersize=8)
            plt.title(f'{tool_name} 请求速率 vs 并发级别 ({target})', fontsize=14)
            plt.xlabel('并发级别', fontsize=12)
            plt.ylabel('请求速率 (请求/秒)', fontsize=12)
        
        plt.grid(True)
        plt.tight_layout()
        
        # 保存图表
        chart_file = f"reports/{tool_name}_{target}_{timestamp}.png"
        plt.savefig(chart_file)
        print(f"性能图表已保存到 {chart_file}")
        
        plt.close()
        return chart_file
    
    except Exception as e:
        print(f"生成图表时出错: {str(e)}")
        return None

def run_concurrency_tests(target, port_levels=None, subdomain_levels=None, vuln_levels=None):
    """运行完整的并发性能测试"""
    # 默认并发级别
    if port_levels is None:
        port_levels = [5, 10, 20, 30]
    
    if subdomain_levels is None:
        subdomain_levels = [5, 10, 20, 30]
    
    if vuln_levels is None:
        vuln_levels = [5, 10, 20, 30]
    
    # 确保工具有执行权限
    for tool_path in [NAABU_PATH, SUBFINDER_PATH, TIDEFINGER_PATH, NUCLEI_PATH]:
        if os.path.exists(tool_path) and not os.access(tool_path, os.X_OK):
            try:
                os.chmod(tool_path, 0o755)
                print(f"已为 {os.path.basename(tool_path)} 添加执行权限")
            except Exception as e:
                print(f"无法为 {os.path.basename(tool_path)} 添加执行权限: {str(e)}")
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    results = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "port_scan_results": [],
        "subdomain_scan_results": [],
        "vulnerability_scan_results": []
    }
    
    # 端口扫描并发测试
    print("\n开始端口扫描并发性能测试...")
    port_results = test_port_scan_concurrency(target, port_levels)
    results["port_scan_results"] = port_results
    
    # 子域名扫描并发测试
    print("\n开始子域名扫描并发性能测试...")
    subdomain_results = test_subdomain_scan_concurrency(target, subdomain_levels)
    results["subdomain_scan_results"] = subdomain_results
    
    # 漏洞扫描并发测试
    print("\n开始漏洞扫描并发性能测试...")
    vuln_results = test_vulnerability_scan_concurrency(target, vuln_levels)
    results["vulnerability_scan_results"] = vuln_results
    
    # 保存结果
    results_file = f"logs/concurrency_test_results_{timestamp}.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n测试结果已保存到 {results_file}")
    
    # 生成图表
    print("\n正在生成性能对比图表...")
    port_chart = generate_concurrency_charts(port_results, "端口扫描", target, timestamp)
    subdomain_chart = generate_concurrency_charts(subdomain_results, "子域名扫描", target, timestamp)
    vuln_chart = generate_concurrency_charts(vuln_results, "漏洞扫描", target, timestamp)
    
    # 输出总结
    print("\n" + "="*50)
    print(f"并发性能测试完成，目标: {target}")
    print("="*50)
    
    # 打印端口扫描最佳配置
    best_port_config = None
    max_ports_per_second = 0
    for r in port_results:
        if r['success'] and r['execution_time'] > 0:
            ports_per_second = 100 / r['execution_time']  # 假设扫描了top-100端口
            if ports_per_second > max_ports_per_second:
                max_ports_per_second = ports_per_second
                best_port_config = r['concurrency']
    
    if best_port_config:
        print(f"\n端口扫描最佳并发配置: {best_port_config} (扫描速率: {max_ports_per_second:.2f} 端口/秒)")
    
    # 打印子域名扫描最佳配置
    best_subdomain_config = None
    max_subdomains = 0
    for r in subdomain_results:
        if r['success'] and r['subdomains_count'] > max_subdomains:
            max_subdomains = r['subdomains_count']
            best_subdomain_config = r['concurrency']
    
    if best_subdomain_config:
        best_time = next((r['execution_time'] for r in subdomain_results if r['concurrency'] == best_subdomain_config), 0)
        print(f"\n子域名扫描最佳并发配置: {best_subdomain_config} (发现 {max_subdomains} 个子域名，耗时: {best_time:.2f}秒)")
    
    # 打印漏洞扫描最佳配置
    best_vuln_config = None
    max_requests_per_second = 0
    for r in vuln_results:
        if r['success'] and r['requests_per_second'] > max_requests_per_second:
            max_requests_per_second = r['requests_per_second']
            best_vuln_config = r['concurrency']
    
    if best_vuln_config:
        print(f"\n漏洞扫描最佳并发配置: {best_vuln_config} (请求速率: {max_requests_per_second:.2f} 请求/秒)")
    
    print("="*50)
    
    return results

def parse_args():
    parser = argparse.ArgumentParser(description='安全工具并发性能测试脚本')
    parser.add_argument('target', help='目标站点或域名')
    parser.add_argument('--port-levels', type=str, help='端口扫描并发级别，用逗号分隔，例如: 10,50,100')
    parser.add_argument('--subdomain-levels', type=str, help='子域名扫描并发级别，用逗号分隔，例如: 10,50,100')
    parser.add_argument('--vuln-levels', type=str, help='漏洞扫描并发级别，用逗号分隔，例如: 10,50,100')
    return parser.parse_args()

def main():
    args = parse_args()
    
    # 解析并发级别
    port_levels = None
    if args.port_levels:
        try:
            port_levels = [int(x.strip()) for x in args.port_levels.split(',')]
        except:
            print("端口扫描并发级别格式无效，使用默认值")
    
    subdomain_levels = None
    if args.subdomain_levels:
        try:
            subdomain_levels = [int(x.strip()) for x in args.subdomain_levels.split(',')]
        except:
            print("子域名扫描并发级别格式无效，使用默认值")
    
    vuln_levels = None
    if args.vuln_levels:
        try:
            vuln_levels = [int(x.strip()) for x in args.vuln_levels.split(',')]
        except:
            print("漏洞扫描并发级别格式无效，使用默认值")
    
    run_concurrency_tests(
        args.target,
        port_levels=port_levels,
        subdomain_levels=subdomain_levels,
        vuln_levels=vuln_levels
    )

if __name__ == "__main__":
    main() 