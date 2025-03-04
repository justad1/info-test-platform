from django.db import models

class SubdomainScan(models.Model):
    """子域名扫描记录"""
    domain = models.CharField(max_length=255, verbose_name='主域名')
    status = models.CharField(max_length=20, verbose_name='扫描状态', 
                            choices=[
                                ('pending', '等待中'),
                                ('running', '扫描中'),
                                ('completed', '已完成'),
                                ('failed', '失败')
                            ])
    result = models.TextField(blank=True, null=True, verbose_name='扫描结果')
    start_time = models.DateTimeField(auto_now_add=True, verbose_name='开始时间')
    end_time = models.DateTimeField(null=True, blank=True, verbose_name='结束时间')
    found_count = models.IntegerField(default=0, verbose_name='发现子域名数量')
    
    class Meta:
        verbose_name = '子域名扫描'
        verbose_name_plural = '子域名扫描'
        ordering = ['-start_time']
    
    def __str__(self):
        return f"{self.domain} - {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}"
