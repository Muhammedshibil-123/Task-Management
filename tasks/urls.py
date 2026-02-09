from django.urls import path
from .views import register_page, login_page, user_page, logout_user
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('register/', register_page, name='register_page'),
    path('', login_page, name='login_page'),
    path('user/', user_page, name='user_page'),
    path('logout/', logout_user, name='logout'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]