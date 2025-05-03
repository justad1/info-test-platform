# 数据库配置
import os

from info_vuln_platform.info_vuln_platform.settings import BASE_DIR


DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
} 