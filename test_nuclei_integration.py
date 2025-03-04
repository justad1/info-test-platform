#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import json
import subprocess
from datetime import datetime

# 添加项目路径到sys.path
sys.path.append(os.path.abspath(os.path.dirname(__file__)))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "info_vuln_platform.info_vuln_platform.settings")

# 初始化Django
import django
django.setup()

from django.utils import timezone
from info_vuln_platform.manager.views_vulnscan import VulnScanApiView

def test_nuclei_integration():
    """测试Nuclei集成"""
    print("开始测试Nuclei集成...")
    
    # 创建VulnScanApiView实例
    view = VulnScanApiView()
    
    # 测试build_command方法
    params = {
        'target': 'example.com',
        'templates': 'technologies',
        'severity': 'info',
        'threads': 10,
        'timeout': 2
    }
    
    cmd = view.build_command(params)
    print(f"构建的命令: {' '.join(cmd)}")
    
    # 执行命令
    print("执行Nuclei扫描...")
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        cwd=os.path.dirname(view.nuclei_path)
    )
    
    stdout, stderr = process.communicate()
    return_code = process.returncode
    
    print(f"命令返回码: {return_code}")
    if stderr:
        print(f"错误输出: {stderr}")
    
    # 解析结果
    print("解析扫描结果...")
    results, severity_distribution = view.parse_results(stdout)
    
    print(f"扫描发现 {len(results)} 个结果")
    print(f"严重级别分布: {severity_distribution}")
    
    # 打印前3个结果（如果有）
    for i, result in enumerate(results[:3]):
        print(f"\n结果 {i+1}:")
        print(json.dumps(result, indent=2, ensure_ascii=False))
    
    return len(results) > 0

if __name__ == "__main__":
    if test_nuclei_integration():
        print("\n集成测试成功！")
    else:
        print("\n集成测试失败：没有发现任何结果")
