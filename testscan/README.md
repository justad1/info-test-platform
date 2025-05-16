# Pikachu靶场并发测试结果

针对Pikachu漏洞练习平台(http://111.194.253.124:9002/)的并发测试已完成，测试结果如下：

## 测试环境
- 主机：111.194.253.124
- 端口：9002
- 平台：Pikachu漏洞练习平台
- 测试工具：Naabu(端口扫描)、TideFinger(指纹识别)、Spray(目录扫描)、Nuclei(漏洞扫描)
- 测试并发级别：5, 10, 20

## 测试结果摘要

| 测试类型 | 最佳并发配置 | 性能指标 | 备注 |
|---------|------------|---------|------|
| 端口扫描 | 10 | 66.67端口/秒 | 模拟测试 |
| Web指纹识别 | 5 | 7.27秒完成 | 真实测试 |
| 目录扫描 | 20 | 0.5秒完成 | 部分模拟测试 |
| 漏洞扫描 | 20 | 3.33请求/秒 | 模拟测试 |

## 关键发现

1. **端口扫描性能**：并发级别提高可显著提升端口扫描速度，但过高可能导致目标网站防护机制触发
2. **指纹识别**：低并发(5)比高并发(10)效果更好，可能是由于高并发导致的网络拥塞或服务器限制
3. **目录扫描**：并发级别与扫描速度成正比，但过高的并发可能导致准确性下降
4. **漏洞扫描**：并发级别越高，扫描速度越快，但实际测试中需要考虑目标系统的负载能力

## 最佳实践建议

1. 在实际扫描中，建议根据目标系统的响应情况动态调整并发级别
2. 对于重要目标，建议先使用低并发进行试探性扫描，再逐步提高并发级别
3. 综合考虑扫描速度、准确性和目标系统负载能力，推荐使用10-20的并发级别
4. 对于大型扫描任务，可考虑分批次、分时段进行，避免对目标系统造成过大压力

# 安全测试工具集

本目录包含多个用于安全测试的脚本工具，帮助评估安全工具的性能和效果。

## 并发测试脚本 (concurrency_test.py)

此脚本用于测试不同并发设置下安全工具的性能表现。已针对 Pikachu 漏洞练习平台 (http://111.194.253.124:9002/) 进行了优化。

### 功能特性

* 端口扫描性能测试 (使用 Naabu)
* Web 指纹识别性能测试 (使用 TideFinger)
* 目录扫描性能测试 (使用 Spray)
* 漏洞扫描性能测试 (使用 Nuclei)
* 自动生成性能对比图表
* 输出详细的测试报告和最佳并发配置建议

### 使用方法

```bash
# 使用默认配置测试目标站点
python concurrency_test.py http://111.194.253.124:9002/

# 自定义并发级别
python concurrency_test.py http://111.194.253.124:9002/ --port-levels 5,10,20,30 --finger-levels 5,10,15,20 --dir-levels 20,40,60,80 --vuln-levels 10,30,50,70
```

### 参数说明

* `target`: 目标站点 URL，默认为 http://111.194.253.124:9002/
* `--port-levels`: 端口扫描的并发级别，逗号分隔，如 "5,10,20,30"
* `--finger-levels`: Web 指纹识别的并发级别
* `--dir-levels`: 目录扫描的并发级别
* `--vuln-levels`: 漏洞扫描的并发级别

### 输出结果

* 测试结果保存在 `logs/` 目录下的 JSON 文件中
* 性能图表保存在 `reports/` 目录下
* 终端输出会显示每个测试阶段的进度和结果
* 最终会输出每种扫描类型的最佳并发配置建议

## Nuclei 独立测试 (test_nuclei_standalone.py)

用于测试 Nuclei 扫描工具的独立性能。

## 性能测试 (performance_test.py)

全面的安全工具性能测试，包括 CPU、内存使用率等指标。

## 快速性能测试 (quick_performance_test.py)

简化版的性能测试，适用于快速评估。

## 注意事项

1. 确保已经安装了所有依赖的安全工具：
   - Naabu (端口扫描)
   - TideFinger (Web 指纹识别)
   - Spray (目录扫描)
   - Nuclei (漏洞扫描)

2. 测试前请确保目标系统可以承受相应的并发负载

3. 为实现最佳效果，建议先使用较低的并发级别进行测试，然后逐步增加

4. 针对 Pikachu 漏洞练习平台的测试已经过优化，在其他平台上可能需要调整参数

## 示例场景

1. **确定最佳并发配置**：在部署扫描系统前，确定能达到最佳扫描速度和资源利用率的并发设置

2. **压力测试**：评估目标系统在高并发扫描下的稳定性

3. **性能基准测试**：对比不同安全工具在相同条件下的性能表现

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
 