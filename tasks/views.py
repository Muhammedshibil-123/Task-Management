from django.shortcuts import render, redirect
from django.contrib import messages
from rest_framework import generics
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from .serializers import UserRegistrationSerializer
from django.contrib.auth import authenticate, get_user_model

User = get_user_model()

class RegisterView(generics.CreateAPIView):
    serializer_class = UserRegistrationSerializer
    permission_classes = [AllowAny]

def register_page(request):
    if request.method == 'POST':
        serializer = UserRegistrationSerializer(data=request.POST)
        if serializer.is_valid():
            serializer.save()
            return redirect('login_page')
        return render(request, 'tasks/register.html', {'errors': serializer.errors})
    return render(request, 'tasks/register.html')

def login_page(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        user = authenticate(request, email=email, password=password)
        
        if user is not None:
            refresh = RefreshToken.for_user(user)
            response = redirect('user_page')
            response.set_cookie('access_token', str(refresh.access_token), httponly=True)
            return response
        else:
            messages.error(request, "Invalid credentials")
            return render(request, 'tasks/login.html')
            
    return render(request, 'tasks/login.html')

def user_page(request):
    token = request.COOKIES.get('access_token')
    if not token:
        return redirect('login_page')
    
    try:
        jwt_auth = JWTAuthentication()
        validated_token = jwt_auth.get_validated_token(token)
        user = jwt_auth.get_user(validated_token)
        return render(request, 'tasks/user_page.html', {'user': user})
    except:
        return redirect('login_page')

def logout_user(request):
    response = redirect('login_page')
    response.delete_cookie('access_token')
    return response