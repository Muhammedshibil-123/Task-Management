from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth import authenticate, get_user_model
from .models import Task
from .serializers import UserRegistrationSerializer

User = get_user_model()

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
            tasks = Task.objects.filter(assigned_to=user)
            response = render(request, 'tasks/user_page.html', {
                'user': user, 
                'tasks': tasks,
                'access_token': str(refresh.access_token) 
            })
            response.set_cookie(
                'refresh_token', 
                str(refresh), 
                httponly=True, 
                samesite='Lax'
            )
            return response
        else:
            messages.error(request, "Invalid credentials")
            return render(request, 'tasks/login.html')
    return render(request, 'tasks/login.html')

def user_page(request):
    token = request.COOKIES.get('refresh_token')
    if not token:
        return redirect('login_page')
    
    try:
        refresh = RefreshToken(token)
        user_id = refresh.payload.get('user_id')
        user = User.objects.get(id=user_id)
        tasks = Task.objects.filter(assigned_to=user)
        return render(request, 'tasks/user_page.html', {'user': user, 'tasks': tasks})
    except Exception:
        return redirect('login_page')

def update_task_status(request, task_id):
    token = request.COOKIES.get('access_token')
    if not token:
        return redirect('login_page')

    task = get_object_or_404(Task, id=task_id)
    if request.method == 'POST':
        report = request.POST.get('completion_report')
        hours = request.POST.get('worked_hours')
        
        task.status = 'COMPLETED'
        task.completion_report = report
        task.worked_hours = hours
        task.save()
        return redirect('user_page')
    
    return render(request, 'tasks/update_task.html', {'task': task})

def admin_dashboard(request):
    token = request.COOKIES.get('access_token')
    jwt_auth = JWTAuthentication()
    validated_token = jwt_auth.get_validated_token(token)
    user = jwt_auth.get_user(validated_token)
    
    if user.role not in ['ADMIN', 'SUPERADMIN']:
        return redirect('user_page')
        
    managed_users = User.objects.filter(assigned_admin=user)
    tasks = Task.objects.filter(assigned_to__in=managed_users)
    return render(request, 'tasks/admin_dashboard.html', {'tasks': tasks})

def superadmin_dashboard(request):
    token = request.COOKIES.get('access_token')
    jwt_auth = JWTAuthentication()
    validated_token = jwt_auth.get_validated_token(token)
    user = jwt_auth.get_user(validated_token)
    
    if user.role != 'SUPERADMIN':
        return redirect('user_page')
        
    users = User.objects.all()
    tasks = Task.objects.all()
    return render(request, 'tasks/superadmin_dashboard.html', {'users': users, 'tasks': tasks})

def logout_user(request):
    response = redirect('login_page')
    response.delete_cookie('refresh_token')
    return response