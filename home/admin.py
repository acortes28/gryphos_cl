from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import UserChangeForm, UserCreationForm
from .models import CustomUser
from .models import Curso, BlogPost

class CustomUserAdmin(BaseUserAdmin):
    form = UserChangeForm
    add_form = UserCreationForm

    # La siguiente configuración determina qué campos se mostrarán en el admin.
    list_display = ('username', 'email', 'phone_number', 'company_name', 'company_rut', 'company_address', 'admin_name', 'is_staff')
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'email', 'phone_number', 'company_name', 'company_rut', 'company_address', 'admin_name')}),
        ('Cursos', {'fields': ('cursos',)}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser',
                                   'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'password1', 'password2', 'email', 'phone_number', 'company_name', 'company_rut', 'company_address', 'admin_name', 'cursos', 'is_staff', 'is_superuser'),
        }),
    )
    search_fields = ('email', 'username')
    ordering = ('email',)
    filter_horizontal = ('cursos',)

class BlogPostAdmin(admin.ModelAdmin):
    list_display = ('title', 'author', 'category', 'created_at', 'is_active', 'views')
    list_filter = ('category', 'is_active', 'created_at')
    search_fields = ('title', 'content')
    readonly_fields = ('views', 'created_at', 'updated_at')
    prepopulated_fields = {'excerpt': ('title',)}
    
    def save_model(self, request, obj, form, change):
        if not change:  # Si es un nuevo post
            obj.author = request.user
        super().save_model(request, obj, form, change)

# Registra tu modelo personalizado y la clase UserAdmin personalizada
admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(Curso)
admin.site.register(BlogPost, BlogPostAdmin)
