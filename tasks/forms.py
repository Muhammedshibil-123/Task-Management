from django import forms
from .models import Task, User

class TaskAssignForm(forms.ModelForm):
    class Meta:
        model = Task
        fields = ['title', 'description', 'due_date', 'assigned_to']
        widgets = {
            'due_date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'title': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'assigned_to': forms.Select(attrs={'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        if user and user.role == 'ADMIN':
            self.fields['assigned_to'].queryset = User.objects.filter(assigned_admin=user)

class TaskCompletionForm(forms.ModelForm):
    class Meta:
        model = Task
        fields = ['worked_hours', 'completion_report']
        widgets = {
            'worked_hours': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.5'}),
            'completion_report': forms.Textarea(attrs={'class': 'form-control', 'rows': 4, 'placeholder': 'I fixed the issues with...'}),
        }