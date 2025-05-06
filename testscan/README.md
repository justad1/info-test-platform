# 安全工具性能测试脚本

这是一个用于测试信息安全扫描工具性能的脚本，主要包括以下几个方面的测试：

1. 端口扫描（naabu）
2. 子域名扫描（subfinder）
3. 指纹识别（TideFinger）
4. 漏洞扫描（nuclei）

## 功能特点

- 支持对每个工具进行单独测试或组合测试
- 记录每个测试的执行时间和性能指标
- 自动生成详细的测试报告
- 支持多次迭代测试以获得更准确的性能数据
- 输出格式化的JSON结果，便于后续分析

## 使用方法

### 基本用法

```bash
python performance_test.py example.com
```

这将对`example.com`进行所有四种测试（端口扫描、子域名扫描、指纹识别和漏洞扫描）。

### 指定测试类型

```bash
# 仅进行端口扫描
python performance_test.py example.com -p

# 仅进行子域名扫描
python performance_test.py example.com -s

# 仅进行指纹识别
python performance_test.py example.com -f

# 仅进行漏洞扫描
python performance_test.py example.com -v

# 组合多个测试，例如同时进行端口扫描和漏洞扫描
python performance_test.py example.com -p -v
```

### 多次迭代测试

使用`-i`或`--iterations`参数指定测试的迭代次数：

```bash
# 进行3次完整测试
python performance_test.py example.com -i 3
```

## 输出结果

脚本会在`logs`目录下生成两种日志文件：

1. `performance_test_[时间戳].log` - 详细的测试过程日志
2. `performance_results_[时间戳].json` - 测试结果的JSON数据

JSON结果结构示例：

```json
{
  "target": "example.com",
  "timestamp": "2023-07-20T14:30:25.123456",
  "iterations": 1,
  "port_scan": [
    {
      "success": true,
      "execution_time": 15.32,
      "open_ports_count": 5,
      "iteration": 1
    }
  ],
  "subdomain_scan": [
    {
      "success": true,
      "execution_time": 23.45,
      "subdomains_count": 12,
      "iteration": 1
    }
  ],
  "fingerprint_scan": [
    {
      "success": true,
      "execution_time": 8.76,
      "iteration": 1
    }
  ],
  "vulnerability_scan": [
    {
      "success": true,
      "execution_time": 45.67,
      "vulnerabilities_count": 3,
      "iteration": 1
    }
  ],
  "port_scan_avg_time": 15.32,
  "subdomain_scan_avg_time": 23.45,
  "fingerprint_scan_avg_time": 8.76,
  "vulnerability_scan_avg_time": 45.67
}
```

## 性能指标

脚本会记录以下性能指标：

1. 端口扫描：扫描速率（端口/秒）
2. 子域名扫描：扫描速率（子域名/秒）
3. 指纹识别：总执行时间
4. 漏洞扫描：扫描速率（请求/秒）和按严重程度统计的漏洞数量

## 环境要求

- Python 3.6+
- 已正确安装和配置的以下工具：
  - naabu (端口扫描)
  - subfinder (子域名扫描)
  - TideFinger (指纹识别)
  - nuclei (漏洞扫描)

## 故障排除

如果遇到执行权限问题，脚本会尝试自动为工具添加执行权限。如果仍然失败，可以手动执行：

```bash
chmod +x info_vuln_platform/sectools/naabu/naabu
chmod +x info_vuln_platform/sectools/subfinder/subfinder
chmod +x info_vuln_platform/sectools/TideFinger_Go/TideFinger_linux_amd64_v3.2.3
chmod +x info_vuln_platform/sectools/Nuclei/nuclei
``` 
 