from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, Task

class CustomUserAdmin(UserAdmin):
    fieldsets = UserAdmin.fieldsets + (
        ('Role Information', {'fields': ('role', 'assigned_admin')}),
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        ('Role Information', {'fields': ('role', 'assigned_admin')}),
    )
    list_display = ('email', 'username', 'role', 'is_staff')

admin.site.register(User, CustomUserAdmin)
admin.site.register(Task)