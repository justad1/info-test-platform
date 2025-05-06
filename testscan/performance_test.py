#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import subprocess
import json
import sys
import time
import argparse
import logging
from datetime import datetime

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"logs/performance_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 工具路径
TOOLS_BASE_DIR = '/root/projects/info-test-platform/info_vuln_platform/sectools'
NAABU_PATH = os.path.join(TOOLS_BASE_DIR, 'naabu/naabu')
SUBFINDER_PATH = os.path.join(TOOLS_BASE_DIR, 'subfinder/subfinder')
TIDEFINGER_PATH = os.path.join(TOOLS_BASE_DIR, 'TideFinger_Go/TideFinger_linux_amd64_v3.2.3')
NUCLEI_PATH = os.path.join(TOOLS_BASE_DIR, 'Nuclei/nuclei')

def measure_performance(func, *args, **kwargs):
    """测量函数执行的性能"""
    start_time = time.time()
    result = func(*args, **kwargs)
    end_time = time.time()
    execution_time = end_time - start_time
    return result, execution_time

def port_scan(target, ports="top-1000", concurrency=25, timeout=5):
    """使用naabu进行端口扫描并测量性能"""
    logger.info(f"开始对 {target} 进行端口扫描测试...")
    
    # 检查naabu是否存在
    if not os.path.exists(NAABU_PATH):
        logger.error(f"错误: naabu工具不存在: {NAABU_PATH}")
        return False, 0, []
    
    # 检查是否可执行
    if not os.access(NAABU_PATH, os.X_OK):
        logger.warning(f"警告: naabu工具没有执行权限，尝试添加执行权限")
        try:
            os.chmod(NAABU_PATH, 0o755)
            logger.info("已添加执行权限")
        except Exception as e:
            logger.error(f"错误: 添加执行权限失败: {str(e)}")
            return False, 0, []
    
    # 构建命令
    cmd = [
        NAABU_PATH,
        '-host', target,
        '-p', ports,
        '-c', str(concurrency),
        '-timeout', str(timeout),
        '-json'
    ]
    
    logger.info(f"执行命令: {' '.join(cmd)}")
    
    try:
        start_time = time.time()
        
        # 执行命令
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            cwd=os.path.dirname(NAABU_PATH)
        )
        
        # 获取输出
        stdout, stderr = process.communicate(timeout=600)  # 最多等待10分钟
        return_code = process.returncode
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        if stderr:
            logger.warning(f"警告输出: {stderr}")
        
        # 解析结果
        open_ports = []
        for line in stdout.splitlines():
            if not line.strip():
                continue
            
            try:
                result = json.loads(line)
                if 'port' in result:
                    open_ports.append(result)
            except json.JSONDecodeError:
                continue
        
        logger.info(f"端口扫描完成，发现 {len(open_ports)} 个开放端口，耗时: {execution_time:.2f}秒")
        
        # 计算每秒扫描端口数
        if execution_time > 0:
            ports_count = int(ports.split('-')[-1]) if '-' in ports else len(ports.split(','))
            ports_per_second = ports_count / execution_time
            logger.info(f"扫描速率: {ports_per_second:.2f} 端口/秒")
        
        return return_code == 0, execution_time, open_ports
    
    except subprocess.TimeoutExpired:
        logger.error("端口扫描超时，已终止")
        return False, 0, []
    except Exception as e:
        logger.error(f"执行端口扫描时出错: {str(e)}")
        return False, 0, []

def subdomain_scan(target, timeout=10, concurrency=25):
    """使用subfinder进行子域名扫描并测量性能"""
    logger.info(f"开始对 {target} 进行子域名扫描测试...")
    
    # 检查subfinder是否存在
    if not os.path.exists(SUBFINDER_PATH):
        logger.error(f"错误: subfinder工具不存在: {SUBFINDER_PATH}")
        return False, 0, []
    
    # 检查是否可执行
    if not os.access(SUBFINDER_PATH, os.X_OK):
        logger.warning(f"警告: subfinder工具没有执行权限，尝试添加执行权限")
        try:
            os.chmod(SUBFINDER_PATH, 0o755)
            logger.info("已添加执行权限")
        except Exception as e:
            logger.error(f"错误: 添加执行权限失败: {str(e)}")
            return False, 0, []
    
    # 构建命令
    cmd = [
        SUBFINDER_PATH,
        '-d', target,
        '-t', str(concurrency),
        '-timeout', str(timeout),
        '-json'
    ]
    
    logger.info(f"执行命令: {' '.join(cmd)}")
    
    try:
        start_time = time.time()
        
        # 执行命令
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            cwd=os.path.dirname(SUBFINDER_PATH)
        )
        
        # 获取输出
        stdout, stderr = process.communicate(timeout=600)  # 最多等待10分钟
        return_code = process.returncode
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        if stderr:
            logger.warning(f"警告输出: {stderr}")
        
        # 解析结果
        subdomains = []
        for line in stdout.splitlines():
            if not line.strip():
                continue
            
            try:
                result = json.loads(line)
                subdomains.append(result)
            except json.JSONDecodeError:
                continue
        
        logger.info(f"子域名扫描完成，发现 {len(subdomains)} 个子域名，耗时: {execution_time:.2f}秒")
        
        # 计算每秒扫描子域名数
        if execution_time > 0 and len(subdomains) > 0:
            domains_per_second = len(subdomains) / execution_time
            logger.info(f"扫描速率: {domains_per_second:.2f} 子域名/秒")
        
        return return_code == 0, execution_time, subdomains
    
    except subprocess.TimeoutExpired:
        logger.error("子域名扫描超时，已终止")
        return False, 0, []
    except Exception as e:
        logger.error(f"执行子域名扫描时出错: {str(e)}")
        return False, 0, []

def fingerprint_scan(target):
    """使用TideFinger进行指纹识别并测量性能"""
    logger.info(f"开始对 {target} 进行指纹识别测试...")
    
    # 检查TideFinger是否存在
    if not os.path.exists(TIDEFINGER_PATH):
        logger.error(f"错误: TideFinger工具不存在: {TIDEFINGER_PATH}")
        return False, 0, {}
    
    # 检查是否可执行
    if not os.access(TIDEFINGER_PATH, os.X_OK):
        logger.warning(f"警告: TideFinger工具没有执行权限，尝试添加执行权限")
        try:
            os.chmod(TIDEFINGER_PATH, 0o755)
            logger.info("已添加执行权限")
        except Exception as e:
            logger.error(f"错误: 添加执行权限失败: {str(e)}")
            return False, 0, {}
    
    # 构建命令
    output_file = f"logs/tidefinger_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    cmd = [
        TIDEFINGER_PATH,
        '-u', target,
        '-o', output_file
    ]
    
    logger.info(f"执行命令: {' '.join(cmd)}")
    
    try:
        start_time = time.time()
        
        # 执行命令
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            cwd=os.path.dirname(TIDEFINGER_PATH)
        )
        
        # 获取输出
        stdout, stderr = process.communicate(timeout=300)  # 最多等待5分钟
        return_code = process.returncode
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        if stderr:
            logger.warning(f"警告输出: {stderr}")
        
        logger.info(f"指纹识别输出: {stdout}")
        
        # 尝试读取输出文件
        fingerprint_results = {}
        if os.path.exists(output_file):
            try:
                with open(output_file, 'r') as f:
                    content = f.read()
                    if content:
                        fingerprint_results = json.loads(content)
            except Exception as e:
                logger.error(f"读取指纹识别结果文件失败: {str(e)}")
        
        logger.info(f"指纹识别完成，耗时: {execution_time:.2f}秒")
        
        return return_code == 0, execution_time, fingerprint_results
    
    except subprocess.TimeoutExpired:
        logger.error("指纹识别超时，已终止")
        return False, 0, {}
    except Exception as e:
        logger.error(f"执行指纹识别时出错: {str(e)}")
        return False, 0, {}

def vulnerability_scan(target, templates="technologies", concurrency=25, timeout=5):
    """使用Nuclei进行漏洞扫描并测量性能"""
    logger.info(f"开始对 {target} 进行漏洞扫描测试...")
    
    # 检查Nuclei是否存在
    if not os.path.exists(NUCLEI_PATH):
        logger.error(f"错误: Nuclei工具不存在: {NUCLEI_PATH}")
        return False, 0, []
    
    # 检查是否可执行
    if not os.access(NUCLEI_PATH, os.X_OK):
        logger.warning(f"警告: Nuclei工具没有执行权限，尝试添加执行权限")
        try:
            os.chmod(NUCLEI_PATH, 0o755)
            logger.info("已添加执行权限")
        except Exception as e:
            logger.error(f"错误: 添加执行权限失败: {str(e)}")
            return False, 0, []
    
    # 构建命令
    cmd = [
        NUCLEI_PATH,
        '-u', target,
        '-t', templates,
        '-c', str(concurrency),
        '-timeout', str(timeout),
        '-stats',
        '-j'
    ]
    
    logger.info(f"执行命令: {' '.join(cmd)}")
    
    try:
        start_time = time.time()
        
        # 执行命令
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            cwd=os.path.dirname(NUCLEI_PATH)
        )
        
        # 获取输出
        stdout, stderr = process.communicate(timeout=600)  # 最多等待10分钟
        return_code = process.returncode
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        if stderr:
            logger.warning(f"警告输出: {stderr}")
        
        # 解析结果
        vulnerabilities = []
        stats = {}
        for line in stdout.splitlines():
            if not line.strip():
                continue
            
            try:
                result = json.loads(line)
                if 'template-id' in result:
                    vulnerabilities.append(result)
                elif 'stats' in result:
                    stats = result['stats']
            except json.JSONDecodeError:
                continue
        
        # 统计漏洞严重程度
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in vulnerabilities:
            if "info" in vuln and "severity" in vuln["info"]:
                severity = vuln["info"]["severity"].lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
        
        logger.info(f"漏洞扫描完成，发现 {len(vulnerabilities)} 个漏洞，耗时: {execution_time:.2f}秒")
        logger.info(f"漏洞严重程度统计: {severity_counts}")
        
        # 计算每秒处理请求数
        requests_per_second = 0
        if 'requests' in stats and execution_time > 0:
            requests_per_second = stats['requests'] / execution_time
            logger.info(f"扫描速率: {requests_per_second:.2f} 请求/秒")
        
        return return_code == 0, execution_time, {"vulnerabilities": vulnerabilities, "stats": stats}
    
    except subprocess.TimeoutExpired:
        logger.error("漏洞扫描超时，已终止")
        return False, 0, []
    except Exception as e:
        logger.error(f"执行漏洞扫描时出错: {str(e)}")
        return False, 0, []

def run_performance_test(target, iterations=1):
    """运行完整的性能测试"""
    results = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "iterations": iterations,
        "port_scan": [],
        "subdomain_scan": [],
        "fingerprint_scan": [],
        "vulnerability_scan": []
    }
    
    logger.info(f"开始对目标 {target} 进行 {iterations} 次性能测试...")
    
    for i in range(iterations):
        logger.info(f"开始第 {i+1}/{iterations} 次测试")
        
        # 端口扫描
        success, execution_time, open_ports = port_scan(target)
        results["port_scan"].append({
            "success": success,
            "execution_time": execution_time,
            "open_ports_count": len(open_ports),
            "iteration": i+1
        })
        
        # 子域名扫描
        success, execution_time, subdomains = subdomain_scan(target)
        results["subdomain_scan"].append({
            "success": success,
            "execution_time": execution_time,
            "subdomains_count": len(subdomains),
            "iteration": i+1
        })
        
        # 指纹识别
        success, execution_time, fingerprints = fingerprint_scan(target)
        results["fingerprint_scan"].append({
            "success": success,
            "execution_time": execution_time,
            "iteration": i+1
        })
        
        # 漏洞扫描
        success, execution_time, vuln_results = vulnerability_scan(target)
        vulns_count = len(vuln_results.get("vulnerabilities", [])) if isinstance(vuln_results, dict) else 0
        results["vulnerability_scan"].append({
            "success": success,
            "execution_time": execution_time,
            "vulnerabilities_count": vulns_count,
            "iteration": i+1
        })
    
    # 计算平均执行时间
    calculate_average_times(results)
    
    # 保存结果到文件
    result_file = f"logs/performance_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(result_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    logger.info(f"性能测试完成，结果已保存到 {result_file}")
    return results

def calculate_average_times(results):
    """计算各个测试项的平均执行时间"""
    for test_type in ["port_scan", "subdomain_scan", "fingerprint_scan", "vulnerability_scan"]:
        execution_times = [test["execution_time"] for test in results[test_type] if test["success"]]
        if execution_times:
            avg_time = sum(execution_times) / len(execution_times)
            results[f"{test_type}_avg_time"] = avg_time
            logger.info(f"{test_type} 平均执行时间: {avg_time:.2f}秒")
        else:
            results[f"{test_type}_avg_time"] = 0
            logger.warning(f"{test_type} 没有成功的测试")

def main():
    parser = argparse.ArgumentParser(description='安全工具性能测试脚本')
    parser.add_argument('target', help='目标站点或域名')
    parser.add_argument('-i', '--iterations', type=int, default=1, help='测试迭代次数')
    parser.add_argument('-p', '--port-scan', action='store_true', help='仅运行端口扫描测试')
    parser.add_argument('-s', '--subdomain-scan', action='store_true', help='仅运行子域名扫描测试')
    parser.add_argument('-f', '--fingerprint-scan', action='store_true', help='仅运行指纹识别测试')
    parser.add_argument('-v', '--vulnerability-scan', action='store_true', help='仅运行漏洞扫描测试')
    
    args = parser.parse_args()
    
    # 创建日志目录
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # 如果没有指定具体测试，则运行全部测试
    if not (args.port_scan or args.subdomain_scan or args.fingerprint_scan or args.vulnerability_scan):
        run_performance_test(args.target, args.iterations)
        return
    
    # 运行指定的测试
    if args.port_scan:
        success, execution_time, _ = port_scan(args.target)
        logger.info(f"端口扫描结果: {'成功' if success else '失败'}, 耗时: {execution_time:.2f}秒")
    
    if args.subdomain_scan:
        success, execution_time, _ = subdomain_scan(args.target)
        logger.info(f"子域名扫描结果: {'成功' if success else '失败'}, 耗时: {execution_time:.2f}秒")
    
    if args.fingerprint_scan:
        success, execution_time, _ = fingerprint_scan(args.target)
        logger.info(f"指纹识别结果: {'成功' if success else '失败'}, 耗时: {execution_time:.2f}秒")
    
    if args.vulnerability_scan:
        success, execution_time, _ = vulnerability_scan(args.target)
        logger.info(f"漏洞扫描结果: {'成功' if success else '失败'}, 耗时: {execution_time:.2f}秒")

if __name__ == "__main__":
    main() 