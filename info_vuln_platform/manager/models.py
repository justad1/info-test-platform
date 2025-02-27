from django.db import models
from django.utils import timezone

# Create your models here.
class User(models.Model):
    username = models.CharField(max_length=50, unique=True, verbose_name='用户名')
    password = models.CharField(max_length=128, verbose_name='密码')
    email = models.EmailField(blank=True, null=True, verbose_name='邮箱')
    is_active = models.BooleanField(default=True, verbose_name='是否激活')
    is_admin = models.BooleanField(default=False, verbose_name='是否管理员')
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='创建时间')
    last_login = models.DateTimeField(blank=True, null=True, verbose_name='最后登录时间')

    class Meta:
        verbose_name = '用户'
        verbose_name_plural = '用户'

    def __str__(self):
        return self.username

class UserLog(models.Model):
    """用户操作日志"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='logs', verbose_name='用户')
    action = models.CharField(max_length=100, verbose_name='操作')
    ip = models.CharField(max_length=50, blank=True, null=True, verbose_name='IP地址')
    details = models.TextField(blank=True, null=True, verbose_name='详细信息')
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='操作时间')

    class Meta:
        verbose_name = '用户日志'
        verbose_name_plural = '用户日志'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.username} - {self.action} - {self.created_at}"

class FingerprintCategory(models.Model):
    """指纹分类"""
    name = models.CharField(max_length=100, unique=True, verbose_name='分类名称')
    description = models.TextField(blank=True, null=True, verbose_name='分类描述')
    create_time = models.DateTimeField(auto_now_add=True, verbose_name='创建时间')
    update_time = models.DateTimeField(auto_now=True, verbose_name='更新时间')

    class Meta:
        verbose_name = '指纹分类'
        verbose_name_plural = '指纹分类'
        ordering = ['name']

    def __str__(self):
        return self.name

class Fingerprint(models.Model):
    """指纹"""
    POSITION_CHOICES = (
        ('header', 'HTTP头部'),
        ('body', '响应体'),
        ('url', 'URL'),
        ('all', '全部'),
    )
    
    name = models.CharField(max_length=100, verbose_name='指纹名称')
    category = models.ForeignKey(FingerprintCategory, on_delete=models.CASCADE, related_name='fingerprints', verbose_name='所属分类')
    rule = models.CharField(max_length=255, verbose_name='匹配规则')
    position = models.CharField(max_length=20, choices=POSITION_CHOICES, default='body', verbose_name='匹配位置')
    description = models.TextField(blank=True, null=True, verbose_name='指纹描述')
    create_time = models.DateTimeField(auto_now_add=True, verbose_name='创建时间')
    update_time = models.DateTimeField(auto_now=True, verbose_name='更新时间')
    
    class Meta:
        verbose_name = '指纹'
        verbose_name_plural = '指纹'
        ordering = ['category', 'name']
        
    def __str__(self):
        return f"{self.name} ({self.category.name})"

class Subdomain(models.Model):
    """子域名"""
    domain = models.CharField(max_length=255, verbose_name='主域名')
    subdomain = models.CharField(max_length=255, verbose_name='子域名')
    ip = models.CharField(max_length=100, blank=True, null=True, verbose_name='IP地址')
    status = models.IntegerField(default=200, blank=True, null=True, verbose_name='状态码')
    title = models.CharField(max_length=255, blank=True, null=True, verbose_name='网站标题')
    server = models.CharField(max_length=255, blank=True, null=True, verbose_name='服务器')
    create_time = models.DateTimeField(auto_now_add=True, verbose_name='创建时间')
    update_time = models.DateTimeField(auto_now=True, verbose_name='更新时间')
    
    class Meta:
        verbose_name = '子域名'
        verbose_name_plural = '子域名'
        ordering = ['domain', 'subdomain']
        unique_together = ('domain', 'subdomain')
    
    def __str__(self):
        return f"{self.subdomain}.{self.domain}"

class PocCategory(models.Model):
    """POC分类"""
    name = models.CharField(max_length=100, unique=True, verbose_name='分类名称')
    description = models.TextField(blank=True, null=True, verbose_name='分类描述')
    create_time = models.DateTimeField(auto_now_add=True, verbose_name='创建时间')
    update_time = models.DateTimeField(auto_now=True, verbose_name='更新时间')

    class Meta:
        verbose_name = 'POC分类'
        verbose_name_plural = 'POC分类'
        ordering = ['name']

    def __str__(self):
        return self.name

class Poc(models.Model):
    """POC"""
    SEVERITY_CHOICES = (
        ('info', '信息'),
        ('low', '低危'),
        ('medium', '中危'),
        ('high', '高危'),
        ('critical', '严重'),
    )
    
    name = models.CharField(max_length=100, verbose_name='POC名称')
    category = models.ForeignKey(PocCategory, on_delete=models.CASCADE, related_name='pocs', verbose_name='所属分类')
    template = models.TextField(verbose_name='Nuclei模板')
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='medium', verbose_name='危害等级')
    description = models.TextField(blank=True, null=True, verbose_name='POC描述')
    create_time = models.DateTimeField(auto_now_add=True, verbose_name='创建时间')
    update_time = models.DateTimeField(auto_now=True, verbose_name='更新时间')
    
    class Meta:
        verbose_name = 'POC'
        verbose_name_plural = 'POC'
        ordering = ['category', 'name']
        
    def __str__(self):
        return f"{self.name} ({self.category.name})"
