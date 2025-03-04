#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import json
import subprocess
import logging
from datetime import datetime

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class NucleiTester:
    """Nuclei测试类，用于测试Nuclei工具的集成"""
    
    def __init__(self):
        """初始化Nuclei测试类"""
        # 设置Nuclei路径
        self.nuclei_path = '/root/project/info-test-platform/info_vuln_platform/sectools/Nuclei/nuclei'
        if not os.path.exists(self.nuclei_path):
            raise FileNotFoundError(f"Nuclei工具不存在: {self.nuclei_path}")
        
        # 检查执行权限
        if not os.access(self.nuclei_path, os.X_OK):
            logger.warning(f"Nuclei工具没有执行权限，尝试添加...")
            try:
                os.chmod(self.nuclei_path, 0o755)
                logger.info("已添加执行权限")
            except Exception as e:
                raise PermissionError(f"无法添加执行权限: {str(e)}")
    
    def build_command(self, params):
        """构建Nuclei命令"""
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
        """解析Nuclei输出结果"""
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
                            'timestamp': datetime.now().isoformat(),
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

def test_nuclei_integration():
    """测试Nuclei集成"""
    print("开始测试Nuclei集成...")
    
    try:
        # 创建NucleiTester实例
        tester = NucleiTester()
        
        # 测试build_command方法
        params = {
            'target': 'example.com',
            'templates': 'technologies',
            'severity': 'info',
            'threads': 10,
            'timeout': 2
        }
        
        cmd = tester.build_command(params)
        print(f"构建的命令: {' '.join(cmd)}")
        
        # 执行命令
        print("执行Nuclei扫描...")
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            cwd=os.path.dirname(tester.nuclei_path)
        )
        
        stdout, stderr = process.communicate()
        return_code = process.returncode
        
        print(f"命令返回码: {return_code}")
        if stderr:
            print(f"错误输出: {stderr}")
        
        # 解析结果
        print("解析扫描结果...")
        results, severity_distribution = tester.parse_results(stdout)
        
        print(f"扫描发现 {len(results)} 个结果")
        print(f"严重级别分布: {severity_distribution}")
        
        # 打印前3个结果（如果有）
        for i, result in enumerate(results[:3]):
            print(f"\n结果 {i+1}:")
            print(json.dumps(result, indent=2, ensure_ascii=False))
        
        return len(results) > 0
    
    except Exception as e:
        print(f"测试过程中发生错误: {str(e)}")
        return False

if __name__ == "__main__":
    if test_nuclei_integration():
        print("\n集成测试成功！")
    else:
        print("\n集成测试失败：没有发现任何结果")
