from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    ROLE_CHOICES = (
        ('SUPERADMIN', 'SuperAdmin'),
        ('ADMIN', 'Admin'),
        ('USER', 'User'),
    )
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='USER')
    assigned_admin = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_users')

    def save(self, *args, **kwargs):
        if not self.pk and not self.is_superuser:
            self.role = 'USER'
        return super().save(*args, **kwargs)

class Task(models.Model):
    STATUS_CHOICES = (
        ('PENDING', 'Pending'),
        ('IN_PROGRESS', 'In Progress'),
        ('COMPLETED', 'Completed'),
    )
    
    title = models.CharField(max_length=255)
    description = models.TextField()
    assigned_to = models.ForeignKey(User, on_delete=models.CASCADE, related_name='tasks')
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_tasks')
    due_date = models.DateField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    completion_report = models.TextField(blank=True, null=True)
    worked_hours = models.DecimalField(max_digits=5, decimal_places=2, blank=True, null=True)

    def __str__(self):
        return self.title