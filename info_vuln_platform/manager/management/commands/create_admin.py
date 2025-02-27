from django.core.management.base import BaseCommand
from manager.models import User
import hashlib
import os

class Command(BaseCommand):
    help = '创建管理员用户'

    def add_arguments(self, parser):
        parser.add_argument('--username', type=str, help='管理员用户名')
        parser.add_argument('--password', type=str, help='管理员密码')
        parser.add_argument('--email', type=str, help='管理员邮箱')

    def handle(self, *args, **options):
        username = options['username'] or 'admin'
        password = options['password'] or 'admin123'
        email = options['email'] or 'admin@example.com'

        # 检查用户是否已存在
        if User.objects.filter(username=username).exists():
            self.stdout.write(self.style.WARNING(f'用户 "{username}" 已存在'))
            return

        # 创建密码哈希
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # 创建管理员用户
        user = User.objects.create(
            username=username,
            password=hashed_password,
            email=email,
            is_active=True,
            is_admin=True
        )

        self.stdout.write(self.style.SUCCESS(f'成功创建管理员用户 "{username}"'))
