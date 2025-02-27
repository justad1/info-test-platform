from django.urls import path
from . import views
from django.views.decorators.csrf import csrf_exempt

urlpatterns = [
    # 登录页面
    path('', views.IndexView.as_view(), name='index'),
    # 登录处理
    path('login/', csrf_exempt(views.IndexView.as_view()), name='login'),
    # 后台首页
    path('dashboard/', views.DashboardView.as_view(), name='dashboard'),
    # 退出登录
    path('logout/', views.LogoutView.as_view(), name='logout'),
    
    # 用户管理页面
    path('user/list/', views.UserListView.as_view(), name='user_list'),
    # 用户日志列表页面
    path('user/logs/', views.UserLogListView.as_view(), name='user_log_list'),
    
    # 用户管理API
    path('api/users/', views.UserApiView.as_view(), name='user_api'),
    path('api/users/<int:user_id>/', views.UserApiView.as_view(), name='user_detail'),
    path('api/users/batch_delete/', views.UserBatchDeleteView.as_view(), name='user_batch_delete'),
    path('api/users/<int:user_id>/toggle_admin/', views.UserToggleAdminView.as_view(), name='user_toggle_admin'),
    path('api/users/<int:user_id>/toggle_active/', views.UserToggleActiveView.as_view(), name='user_toggle_active'),
    
    # 用户日志API
    path('api/logs/', views.UserLogApiView.as_view(), name='user_logs'),
    
    # 个人信息页面
    path('profile/', views.ProfileView.as_view(), name='profile'),
    # 个人信息API
    path('api/profile/', csrf_exempt(views.ProfileApiView.as_view()), name='profile_api'),
    
    # 修改密码页面
    path('change_password/', views.ChangePasswordView.as_view(), name='change_password'),
    # 修改密码API
    path('api/change_password/', csrf_exempt(views.ChangePasswordApiView.as_view()), name='change_password_api'),
    
    # 指纹分类页面
    path('fingerprint/category/', views.FingerprintCategoryView.as_view(), name='fingerprint_category'),
    # 指纹管理页面
    path('fingerprint/', views.FingerprintManagementView.as_view(), name='fingerprint_management'),
    
    # 指纹分类API
    path('api/fingerprint/categories/', csrf_exempt(views.FingerprintCategoryApiView.as_view()), name='fingerprint_category_api'),
    path('api/fingerprint/categories/<int:category_id>/', csrf_exempt(views.FingerprintCategoryApiView.as_view()), name='fingerprint_category_detail'),
    
    # 指纹API
    path('api/fingerprint/', csrf_exempt(views.FingerprintApiView.as_view()), name='fingerprint_api'),
    path('api/fingerprint/<int:fingerprint_id>/', csrf_exempt(views.FingerprintApiView.as_view()), name='fingerprint_detail'),
    
    # 子域名管理页面
    path('subdomain/', views.SubdomainView.as_view(), name='subdomain'),
    
    # 子域名API
    path('api/subdomain/', csrf_exempt(views.SubdomainApiView.as_view()), name='subdomain_api'),
    path('api/subdomain/<int:subdomain_id>/', csrf_exempt(views.SubdomainApiView.as_view()), name='subdomain_detail'),
    
    # POC分类页面
    path('poc/category/', views.PocCategoryView.as_view(), name='poc_category'),
    # POC管理页面
    path('poc/', views.PocManagementView.as_view(), name='poc_management'),
    
    # POC分类API
    path('api/poc/categories/', csrf_exempt(views.PocCategoryApiView.as_view()), name='poc_category_api'),
    path('api/poc/categories/<int:category_id>/', csrf_exempt(views.PocCategoryApiView.as_view()), name='poc_category_detail'),
    
    # POC API
    path('api/poc/', csrf_exempt(views.PocApiView.as_view()), name='poc_api'),
    path('api/poc/<int:poc_id>/', csrf_exempt(views.PocApiView.as_view()), name='poc_detail'),
]