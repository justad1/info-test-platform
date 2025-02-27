from django.db import models

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
