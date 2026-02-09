from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth import authenticate, get_user_model
from .models import Task
from .serializers import UserRegistrationSerializer
from .forms import TaskAssignForm, TaskCompletionForm

User = get_user_model()

def get_current_user(request):
    token = request.COOKIES.get('access_token')
    if not token:
        return None
    try:
        jwt_auth = JWTAuthentication()
        validated_token = jwt_auth.get_validated_token(token)
        return jwt_auth.get_user(validated_token)
    except:
        return None

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
            if user.role == 'SUPERADMIN':
                next_page = 'superadmin_dashboard'
            elif user.role == 'ADMIN':
                next_page = 'admin_dashboard'
            else:
                next_page = 'user_page'
                
            response = redirect(next_page)
            response.set_cookie('access_token', str(refresh.access_token), httponly=True, samesite='Lax')
            response.set_cookie('refresh_token', str(refresh), httponly=True, samesite='Lax')
            return response
        else:
            messages.error(request, "Invalid credentials")
    return render(request, 'tasks/login.html')

def logout_user(request):
    response = redirect('login_page')
    response.delete_cookie('access_token')
    response.delete_cookie('refresh_token')
    return response

def user_page(request):
    user = get_current_user(request)
    if not user:
        return redirect('login_page')
    
    tasks = Task.objects.filter(assigned_to=user).order_by('-id')
    return render(request, 'tasks/user_page.html', {'user': user, 'tasks': tasks})

def update_task_status(request, task_id):
    user = get_current_user(request)
    if not user:
        return redirect('login_page')

    task = get_object_or_404(Task, id=task_id, assigned_to=user)
    
    if request.method == 'POST':
        form = TaskCompletionForm(request.POST, instance=task)
        if form.is_valid():
            task = form.save(commit=False)
            task.status = 'COMPLETED'
            task.save()
            return redirect('user_page')
    else:
        form = TaskCompletionForm(instance=task)
    
    return render(request, 'tasks/update_task.html', {'task': task, 'form': form})

def superadmin_dashboard(request):
    user = get_current_user(request)
    if not user or user.role != 'SUPERADMIN':
        return redirect('login_page')

    tab = request.GET.get('tab', 'details') 
    
    context = {'user': user, 'tab': tab}
    
    if tab == 'users':
        context['users'] = User.objects.all().exclude(id=user.id)
    elif tab == 'assign':
        context['form'] = TaskAssignForm(user=user)
    else: 
        context['tasks'] = Task.objects.all().order_by('-id')
        
    return render(request, 'tasks/superadmin_dashboard.html', context)

def admin_dashboard(request):
    user = get_current_user(request)
    if not user or user.role != 'ADMIN':
        return redirect('login_page')

    tab = request.GET.get('tab', 'details')
    
    context = {'user': user, 'tab': tab}
    
    if tab == 'assign':
        context['form'] = TaskAssignForm(user=user)
    else:
        managed_users = User.objects.filter(assigned_admin=user)
        context['tasks'] = Task.objects.filter(assigned_to__in=managed_users).order_by('-id')

    return render(request, 'tasks/admin_dashboard.html', context)

def assign_task(request):
    user = get_current_user(request)
    if not user or user.role not in ['SUPERADMIN', 'ADMIN']:
        return redirect('login_page')
        
    if request.method == 'POST':
        form = TaskAssignForm(request.POST, user=user)
        if form.is_valid():
            task = form.save(commit=False)
            task.created_by = user
            task.save()
            if user.role == 'SUPERADMIN':
                return redirect('/dashboard/superadmin/?tab=details')
            else:
                return redirect('/dashboard/admin/?tab=details')
    
    return redirect('login_page')

def delete_user(request, user_id):
    user = get_current_user(request)
    if not user or user.role != 'SUPERADMIN':
        return redirect('login_page')
        
    if request.method == 'POST':
        user_to_delete = get_object_or_404(User, id=user_id)
        user_to_delete.delete()
        
    return redirect('/dashboard/superadmin/?tab=users')

def change_user_role(request):
    user = get_current_user(request)
    if not user or user.role != 'SUPERADMIN':
        return redirect('login_page')
        
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        new_role = request.POST.get('role')
        target_user = get_object_or_404(User, id=user_id)
        target_user.role = new_role
        if new_role == 'ADMIN':
            target_user.assigned_admin = None 
        target_user.save()
        
    return redirect('/dashboard/superadmin/?tab=users')