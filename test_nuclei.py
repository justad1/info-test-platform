#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import subprocess
import json
import sys

def test_nuclei():
    """测试Nuclei工具是否能够正常工作"""
    # Nuclei工具路径
    nuclei_path = '/root/project/info-test-platform/info_vuln_platform/sectools/Nuclei/nuclei'
    
    # 检查Nuclei是否存在
    if not os.path.exists(nuclei_path):
        print(f"错误: Nuclei工具不存在: {nuclei_path}")
        return False
    
    # 检查Nuclei是否可执行
    if not os.access(nuclei_path, os.X_OK):
        print(f"警告: Nuclei工具没有执行权限，尝试添加执行权限")
        try:
            os.chmod(nuclei_path, 0o755)
            print("已添加执行权限")
        except Exception as e:
            print(f"错误: 添加执行权限失败: {str(e)}")
            return False
    
    # 构建测试命令 - 使用-version参数测试
    cmd = [nuclei_path, '-version']
    print(f"执行命令: {' '.join(cmd)}")
    
    try:
        # 执行命令
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            cwd=os.path.dirname(nuclei_path)
        )
        
        # 获取输出
        stdout, stderr = process.communicate()
        return_code = process.returncode
        
        print(f"返回码: {return_code}")
        print(f"标准输出: {stdout}")
        
        if stderr:
            print(f"错误输出: {stderr}")
        
        if return_code == 0:
            print("Nuclei工具测试成功!")
            return True
        else:
            print(f"Nuclei工具测试失败，返回码: {return_code}")
            return False
    
    except Exception as e:
        print(f"执行Nuclei命令时出错: {str(e)}")
        return False

def test_nuclei_scan(target="example.com"):
    """测试Nuclei扫描功能"""
    # Nuclei工具路径
    nuclei_path = '/root/project/info-test-platform/info_vuln_platform/sectools/Nuclei/nuclei'
    
    # 构建扫描命令
    cmd = [
        nuclei_path,
        '-u', target,
        '-t', 'technologies',  # 只使用技术识别模板，速度快
        '-c', '10',            # 线程数
        '-timeout', '2',       # 超时时间(分钟)
        '-j'                   # 以JSON格式输出结果
    ]
    
    print(f"执行扫描命令: {' '.join(cmd)}")
    
    try:
        # 执行命令
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            cwd=os.path.dirname(nuclei_path)
        )
        
        # 获取输出
        stdout, stderr = process.communicate(timeout=180)  # 最多等待3分钟
        return_code = process.returncode
        
        print(f"扫描返回码: {return_code}")
        
        if stderr:
            print(f"扫描错误输出: {stderr}")
        
        # 解析结果
        results = []
        for line in stdout.splitlines():
            if not line.strip():
                continue
            
            # 跳过非JSON行（如标志行和日志行）
            if line.startswith('[') and not line.startswith('[{'):
                continue
                
            try:
                result = json.loads(line)
                # 检查是否是结果行（而不是统计信息行）
                if 'template-id' in result or 'matcher-name' in result:
                    results.append(result)
            except json.JSONDecodeError:
                # 如果不是JSON格式，可能是一个漏洞发现的文本行
                if '] [http] [' in line:
                    parts = line.split('] [http] [')
                    if len(parts) >= 2:
                        template_id = parts[0].strip('[').strip()
                        severity = parts[1].strip(']').strip()
                        url = parts[-1].strip()
                        results.append({
                            'template-id': template_id,
                            'info': {'severity': severity},
                            'host': url,
                            'matched': url,
                            'type': 'http'
                        })
                        print(f"解析到非JSON格式的漏洞发现: {line}")
                    continue
        
        print(f"扫描发现 {len(results)} 个结果")
        
        # 打印前3个结果（如果有）
        for i, result in enumerate(results[:3]):
            print(f"\n结果 {i+1}:")
            print(json.dumps(result, indent=2, ensure_ascii=False))
        
        if return_code == 0:
            print("Nuclei扫描测试成功!")
            return True
        else:
            print(f"Nuclei扫描测试失败，返回码: {return_code}")
            return False
    
    except subprocess.TimeoutExpired:
        print("扫描超时，已终止")
        return False
    except Exception as e:
        print(f"执行Nuclei扫描时出错: {str(e)}")
        return False

if __name__ == "__main__":
    # 测试Nuclei工具
    if not test_nuclei():
        sys.exit(1)
    
    # 测试Nuclei扫描功能
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    test_nuclei_scan(target)
