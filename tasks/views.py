from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth import authenticate, get_user_model
from .models import Task
from .serializers import UserRegistrationSerializer, TaskSerializer, TaskReportSerializer
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
        context['admins'] = User.objects.filter(role='ADMIN')
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
        assigned_admin_id = request.POST.get('assigned_admin')
        
        target_user = get_object_or_404(User, id=user_id)
        target_user.role = new_role
        
        if new_role == 'USER' and assigned_admin_id:
             admin_user = get_object_or_404(User, id=assigned_admin_id, role='ADMIN')
             target_user.assigned_admin = admin_user
        else:
             target_user.assigned_admin = None
             
        target_user.save()
        
    return redirect('/dashboard/superadmin/?tab=users')

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def api_task_list(request):
    tasks = Task.objects.filter(assigned_to=request.user)
    serializer = TaskSerializer(tasks, many=True)
    return Response(serializer.data)

@api_view(['PUT'])
@permission_classes([permissions.IsAuthenticated])
def api_task_update(request, pk):
    task = get_object_or_404(Task, pk=pk, assigned_to=request.user)
    
    data = request.data.copy()
    data['status'] = 'COMPLETED'
    
    serializer = TaskSerializer(task, data=data, partial=True)
    if serializer.is_valid():
        if not data.get('completion_report') or not data.get('worked_hours'):
             return Response({"error": "Completion report and worked hours are required."}, status=status.HTTP_400_BAD_REQUEST)
        
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def api_task_report(request, pk):
    if request.user.role not in ['SUPERADMIN', 'ADMIN']:
        return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
        
    task = get_object_or_404(Task, pk=pk)
    
    if request.user.role == 'ADMIN':
         if task.assigned_to.assigned_admin != request.user:
             return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
             
    if task.status != 'COMPLETED':
         return Response({"error": "Task is not completed"}, status=status.HTTP_400_BAD_REQUEST)

    serializer = TaskReportSerializer(task)
    return Response(serializer.data)