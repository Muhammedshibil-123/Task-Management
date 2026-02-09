from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_page, name='login_page'),
    path('register/', views.register_page, name='register_page'),
    path('user/', views.user_page, name='user_page'),
    path('task/update/<int:task_id>/', views.update_task_status, name='update_task'),
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('superadmin-dashboard/', views.superadmin_dashboard, name='superadmin_dashboard'),
    path('logout/', views.logout_user, name='logout'),
]