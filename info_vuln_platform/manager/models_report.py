from django.db import models
from django.utils import timezone

class ScanReport(models.Model):
    """扫描报告模型"""
    REPORT_TYPE_CHOICES = (
        ('subdomain', '子域名扫描'),
        ('portscan', '端口扫描'),
        ('dirscan', '目录扫描'),
        ('fingerprint', '指纹识别'),
        ('vulnscan', '漏洞扫描'),
    )
    
    title = models.CharField(max_length=255, verbose_name='报告标题')
    report_type = models.CharField(max_length=20, choices=REPORT_TYPE_CHOICES, verbose_name='报告类型')
    target = models.CharField(max_length=255, verbose_name='扫描目标')
    scan_time = models.DateTimeField(verbose_name='扫描时间')
    content = models.TextField(verbose_name='报告内容')
    create_time = models.DateTimeField(auto_now_add=True, verbose_name='创建时间')
    update_time = models.DateTimeField(auto_now=True, verbose_name='更新时间')
    
    class Meta:
        verbose_name = '扫描报告'
        verbose_name_plural = '扫描报告'
        ordering = ['-create_time']
    
    def __str__(self):
        return f"{self.title} - {self.report_type}"

class VulnerabilityReport(models.Model):
    """漏洞报告模型"""
    SEVERITY_CHOICES = (
        ('info', '信息'),
        ('low', '低危'),
        ('medium', '中危'),
        ('high', '高危'),
        ('critical', '严重'),
    )
    
    title = models.CharField(max_length=255, verbose_name='报告标题')
    target = models.CharField(max_length=255, verbose_name='目标')
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='medium', verbose_name='危害等级')
    description = models.TextField(verbose_name='漏洞描述')
    solution = models.TextField(verbose_name='修复建议')
    poc = models.TextField(blank=True, null=True, verbose_name='验证POC')
    create_time = models.DateTimeField(auto_now_add=True, verbose_name='创建时间')
    update_time = models.DateTimeField(auto_now=True, verbose_name='更新时间')
    
    class Meta:
        verbose_name = '漏洞报告'
        verbose_name_plural = '漏洞报告'
        ordering = ['-create_time']
    
    def __str__(self):
        return f"{self.title} - {self.severity}" 