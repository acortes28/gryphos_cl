from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import UserChangeForm, UserCreationForm
from .models import CustomUser

class CustomUserAdmin(BaseUserAdmin):
    form = UserChangeForm
    add_form = UserCreationForm

    # La siguiente configuración determina qué campos se mostrarán en el admin.
    list_display = ('username', 'email', 'phone_number', 'company_name', 'company_rut', 'company_address', 'admin_name', 'is_staff')
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'email', 'phone_number', 'company_name', 'company_rut', 'company_address', 'admin_name')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser',
                                   'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'password1', 'password2', 'email', 'phone_number', 'company_name', 'company_rut', 'company_address', 'admin_name', 'is_staff', 'is_superuser'),
        }),
    )
    search_fields = ('email', 'username')
    ordering = ('email',)
    filter_horizontal = ()

# Registra tu modelo personalizado y la clase UserAdmin personalizada
admin.site.register(CustomUser, CustomUserAdmin)
