from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import UserChangeForm, UserCreationForm
from django import forms
from .models import CustomUser
from .models import Curso, BlogPost, Videollamada, InscripcionCurso

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

class VideollamadaInline(admin.TabularInline):
    model = Videollamada
    extra = 1
    fields = ('dia_semana', 'hora_inicio', 'hora_fin', 'link_videollamada', 'activa', 'descripcion')
    
    def get_formset(self, request, obj=None, **kwargs):
        formset = super().get_formset(request, obj, **kwargs)
        form = formset.form
        
        # Hacer el enlace requerido si la videollamada está activa
        def clean_link_videollamada(self):
            link = self.cleaned_data.get('link_videollamada')
            activa = self.cleaned_data.get('activa')
            if activa and not link:
                raise forms.ValidationError('Una videollamada activa debe tener un enlace configurado.')
            return link
        
        form.clean_link_videollamada = clean_link_videollamada
        return formset

class CursoAdmin(admin.ModelAdmin):
    list_display = ('nombre', 'docente_nombre', 'precio', 'fecha_inicio', 'fecha_fin', 'activo', 'modalidad', 'nivel')
    list_filter = ('activo', 'modalidad', 'nivel', 'fecha_inicio')
    search_fields = ('nombre', 'docente_nombre', 'descripcion')
    inlines = [VideollamadaInline]
    fieldsets = (
        ('Información Básica', {
            'fields': ('nombre', 'descripcion', 'activo')
        }),
        ('Fechas', {
            'fields': ('fecha_inicio', 'fecha_fin', 'dias_plazo_pago')
        }),
        ('Información Comercial', {
            'fields': ('precio',)
        }),
        ('Información del Docente', {
            'fields': ('docente_nombre', 'docente_titulos', 'docente_trayectoria', 'docente_foto')
        }),
        ('Detalles del Curso', {
            'fields': ('duracion', 'modalidad', 'nivel', 'requisitos')
        }),
        ('Material del Curso', {
            'fields': ('material_introductorio', 'material_curso', 'archivo_introductorio', 'archivo_curso')
        }),
    )

class BlogPostAdmin(admin.ModelAdmin):
    list_display = ('title', 'author', 'category', 'created_at', 'is_active', 'views')
    list_filter = ('category', 'is_active', 'created_at')
    search_fields = ('title', 'content', 'author__username')
    prepopulated_fields = {'excerpt': ('title',)}
    
    def save_model(self, request, obj, form, change):
        if not change:  # Si es un nuevo post
            obj.author = request.user
        super().save_model(request, obj, form, change)

class VideollamadaAdmin(admin.ModelAdmin):
    list_display = ('curso', 'dia_semana', 'hora_inicio', 'hora_fin', 'activa', 'descripcion')
    list_filter = ('activa', 'dia_semana', 'curso')
    search_fields = ('curso__nombre', 'descripcion')
    ordering = ('curso', 'dia_semana', 'hora_inicio')

class InscripcionCursoAdmin(admin.ModelAdmin):
    list_display = ('nombre_interesado', 'nombre_empresa', 'curso', 'estado', 'fecha_solicitud', 'fecha_pago', 'usuario_creado')
    list_filter = ('estado', 'curso', 'fecha_solicitud', 'fecha_pago')
    search_fields = ('nombre_interesado', 'nombre_empresa', 'correo_contacto', 'curso__nombre')
    readonly_fields = ('fecha_solicitud', 'fecha_pago', 'usuario_creado')
    ordering = ('-fecha_solicitud',)
    
    fieldsets = (
        ('Información del Interesado', {
            'fields': ('nombre_interesado', 'nombre_empresa', 'telefono_contacto', 'correo_contacto')
        }),
        ('Información del Curso', {
            'fields': ('curso', 'estado')
        }),
        ('Fechas', {
            'fields': ('fecha_solicitud', 'fecha_pago'),
            'classes': ('collapse',)
        }),
        ('Usuario Creado', {
            'fields': ('usuario_creado',),
            'classes': ('collapse',)
        }),
        ('Observaciones', {
            'fields': ('observaciones',),
            'classes': ('collapse',)
        }),
    )
    
    actions = ['marcar_como_pagado', 'marcar_como_cancelado']
    
    def marcar_como_pagado(self, request, queryset):
        """Acción para marcar inscripciones como pagadas"""
        from django.contrib import messages
        
        for inscripcion in queryset.filter(estado='pendiente'):
            user, password_temp = inscripcion.marcar_como_pagado()
            if user:
                if password_temp:
                    # Usuario nuevo creado
                    self.message_user(
                        request, 
                        f'Inscripción de {inscripcion.nombre_interesado} marcada como pagada. Usuario creado: {user.username}',
                        messages.SUCCESS
                    )
                else:
                    # Usuario existente reutilizado
                    self.message_user(
                        request, 
                        f'Inscripción de {inscripcion.nombre_interesado} marcada como pagada. Usuario existente reutilizado: {user.username}',
                        messages.SUCCESS
                    )
            else:
                self.message_user(
                    request, 
                    f'Error al procesar inscripción de {inscripcion.nombre_interesado}',
                    messages.ERROR
                )
    
    marcar_como_pagado.short_description = "Marcar inscripciones seleccionadas como pagadas"
    
    def marcar_como_cancelado(self, request, queryset):
        """Acción para marcar inscripciones como canceladas"""
        updated = queryset.update(estado='cancelado')
        self.message_user(
            request, 
            f'{updated} inscripción(es) marcada(s) como cancelada(s)',
            messages.SUCCESS
        )
    
    marcar_como_cancelado.short_description = "Marcar inscripciones seleccionadas como canceladas"

# Registra tu modelo personalizado y la clase UserAdmin personalizada
admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(Curso, CursoAdmin)
admin.site.register(BlogPost, BlogPostAdmin)
admin.site.register(Videollamada, VideollamadaAdmin)
admin.site.register(InscripcionCurso, InscripcionCursoAdmin)
