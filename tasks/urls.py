from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_page, name='login_page'),
    path('register/', views.register_page, name='register_page'),
    path('logout/', views.logout_user, name='logout'),
    
    path('dashboard/user/', views.user_page, name='user_page'),
    path('dashboard/admin/', views.admin_dashboard, name='admin_dashboard'),
    path('dashboard/superadmin/', views.superadmin_dashboard, name='superadmin_dashboard'),
    
    path('task/assign/', views.assign_task, name='assign_task'),
    path('task/update/<int:task_id>/', views.update_task_status, name='update_task'),
    
    path('user/delete/<int:user_id>/', views.delete_user, name='delete_user'),
    path('user/change-role/', views.change_user_role, name='change_user_role'),
]