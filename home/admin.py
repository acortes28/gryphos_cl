from django.contrib import admin, messages
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import UserChangeForm, UserCreationForm
from django import forms
from .models import CustomUser
from .models import Curso, BlogPost, Videollamada, InscripcionCurso, Rubrica, CriterioRubrica, Esperable, Asignatura, ObjetivoAprendizaje

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
    list_display = ('nombre','codigo' ,'asignatura', 'docente_nombre', 'precio', 'fecha_inicio', 'fecha_fin', 'activo', 'modalidad', 'nivel')
    list_filter = ('activo', 'modalidad', 'nivel', 'fecha_inicio', 'asignatura')
    search_fields = ('nombre', 'docente_nombre', 'descripcion', 'asignatura__nombre')
    inlines = [VideollamadaInline]
    fieldsets = (
        ('Información Básica', {
            'fields': ('nombre', 'codigo', 'descripcion', 'activo', 'asignatura')
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
            'fields': ('contenido', 'archivo_introductorio')
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

class CursoInline(admin.TabularInline):
    model = Curso
    extra = 0
    fields = ('nombre', 'codigo', 'docente_nombre', 'activo', 'fecha_inicio', 'fecha_fin')
    readonly_fields = ('nombre', 'codigo', 'docente_nombre', 'activo', 'fecha_inicio', 'fecha_fin')
    can_delete = False
    max_num = 0

class AsignaturaAdmin(admin.ModelAdmin):
    list_display = ('codigo', 'nombre', 'area_conocimiento', 'activa', 'get_cursos_count', 'get_evaluaciones_count', 'creado_por')
    list_filter = ('activa', 'area_conocimiento', 'fecha_creacion', 'creado_por')
    search_fields = ('nombre', 'codigo', 'descripcion', 'area_conocimiento')
    readonly_fields = ('fecha_creacion', 'fecha_modificacion')
    ordering = ('codigo', 'nombre')
    inlines = [CursoInline]
    
    fieldsets = (
        ('Información Básica', {
            'fields': ('codigo', 'nombre', 'descripcion', 'activa')
        }),
        ('Detalles Académicos', {
            'fields': ('area_conocimiento',)
        }),
        ('Información del Sistema', {
            'fields': ('creado_por', 'fecha_creacion', 'fecha_modificacion'),
            'classes': ('collapse',)
        }),
    )
    
    def get_cursos_count(self, obj):
        return obj.get_cursos_count()
    get_cursos_count.short_description = 'Cursos'
    
    def get_evaluaciones_count(self, obj):
        return obj.get_evaluaciones_count()
    get_evaluaciones_count.short_description = 'Evaluaciones'
    
    def save_model(self, request, obj, form, change):
        if not change:  # Si es una nueva asignatura
            obj.creado_por = request.user
        super().save_model(request, obj, form, change)

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
admin.site.register(Asignatura, AsignaturaAdmin)
admin.site.register(Curso, CursoAdmin)
admin.site.register(BlogPost, BlogPostAdmin)
admin.site.register(Videollamada, VideollamadaAdmin)
admin.site.register(InscripcionCurso, InscripcionCursoAdmin)

# ============================================================================
# ADMIN PARA EL SISTEMA DE TICKETS DE SOPORTE
# ============================================================================

from .models import TicketSoporte, ComentarioTicket, ClasificacionTicket, SubclasificacionTicket

class ComentarioTicketInline(admin.TabularInline):
    model = ComentarioTicket
    extra = 0
    readonly_fields = ('autor', 'fecha_creacion', 'fecha_actualizacion')
    fields = ('autor', 'contenido', 'es_interno', 'fecha_creacion')
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        # Mostrar solo comentarios no internos o comentarios internos si el usuario es staff
        if request.user.is_staff or request.user.is_superuser:
            return qs
        return qs.filter(es_interno=False)

class TicketSoporteAdmin(admin.ModelAdmin):
    list_display = ('id', 'titulo', 'usuario', 'curso', 'clasificacion', 'estado', 'prioridad', 'asignado_a', 'fecha_creacion')
    list_filter = ('estado', 'prioridad', 'clasificacion', 'curso', 'fecha_creacion', 'asignado_a')
    search_fields = ('titulo', 'descripcion', 'usuario__username', 'usuario__first_name', 'usuario__last_name')
    readonly_fields = ('fecha_creacion', 'fecha_actualizacion', 'fecha_resolucion')
    ordering = ('-fecha_creacion',)
    inlines = [ComentarioTicketInline]
    
    fieldsets = (
        ('Información del Ticket', {
            'fields': ('titulo', 'descripcion', 'clasificacion', 'subclasificacion')
        }),
        ('Estado y Prioridad', {
            'fields': ('estado', 'prioridad', 'asignado_a')
        }),
        ('Información del Usuario', {
            'fields': ('usuario', 'curso')
        }),
        ('Fechas', {
            'fields': ('fecha_creacion', 'fecha_actualizacion', 'fecha_resolucion'),
            'classes': ('collapse',)
        }),
    )
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        # Los usuarios normales solo ven sus propios tickets
        if not (request.user.is_staff or request.user.is_superuser):
            return qs.filter(usuario=request.user)
        return qs
    
    def save_model(self, request, obj, form, change):
        if not change:  # Si es un nuevo ticket
            obj.usuario = request.user
        super().save_model(request, obj, form, change)

class ComentarioTicketAdmin(admin.ModelAdmin):
    list_display = ('ticket', 'autor', 'es_interno', 'fecha_creacion')
    list_filter = ('es_interno', 'fecha_creacion', 'ticket__estado')
    search_fields = ('contenido', 'autor__username', 'ticket__titulo')
    readonly_fields = ('fecha_creacion', 'fecha_actualizacion')
    ordering = ('-fecha_creacion',)
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        # Los usuarios normales solo ven comentarios no internos de sus tickets
        if not (request.user.is_staff or request.user.is_superuser):
            return qs.filter(ticket__usuario=request.user, es_interno=False)
        return qs

class SubclasificacionTicketInline(admin.TabularInline):
    model = SubclasificacionTicket
    extra = 1
    fields = ('nombre', 'descripcion', 'activa')

class ClasificacionTicketAdmin(admin.ModelAdmin):
    list_display = ('nombre', 'descripcion', 'activa', 'get_subclasificaciones_count')
    list_filter = ('activa',)
    search_fields = ('nombre', 'descripcion')
    inlines = [SubclasificacionTicketInline]
    
    def get_subclasificaciones_count(self, obj):
        return obj.subclasificaciones.count()
    get_subclasificaciones_count.short_description = 'Subclasificaciones'

class SubclasificacionTicketAdmin(admin.ModelAdmin):
    list_display = ('nombre', 'clasificacion', 'activa')
    list_filter = ('activa', 'clasificacion')
    search_fields = ('nombre', 'clasificacion__nombre')
    ordering = ('clasificacion', 'nombre')

# Registrar los modelos de tickets
admin.site.register(TicketSoporte, TicketSoporteAdmin)
admin.site.register(ComentarioTicket, ComentarioTicketAdmin)
admin.site.register(ClasificacionTicket, ClasificacionTicketAdmin)
admin.site.register(SubclasificacionTicket, SubclasificacionTicketAdmin)

# Configuraciones para modelos de rúbricas
class ObjetivoAprendizajeInline(admin.TabularInline):
    model = ObjetivoAprendizaje
    extra = 1
    fields = ('nombre', 'descripcion', 'activo')

class EsperableInline(admin.TabularInline):
    model = Esperable
    extra = 1
    fields = ('nivel', 'descripcion', 'puntaje')

class CriterioRubricaAdmin(admin.ModelAdmin):
    list_display = ('nombre', 'rubrica', 'objetivo_aprendizaje')
    list_filter = ('rubrica', 'objetivo_aprendizaje')
    search_fields = ('nombre', 'objetivo', 'rubrica__nombre', 'objetivo_aprendizaje__nombre')
    ordering = ('rubrica',)
    inlines = [EsperableInline] 
    
    fieldsets = (
        ('Información Básica', {
            'fields': ('rubrica', 'nombre', 'objetivo', 'puntaje')
        }),
        ('Objetivo de Aprendizaje', {
            'fields': ('objetivo_aprendizaje',)
        }),
    )

class RubricaAdmin(admin.ModelAdmin):
    list_display = ('nombre', 'evaluacion', 'creado_por', 'fecha_creacion', 'activa')
    list_filter = ('activa', 'fecha_creacion', 'evaluacion__curso')
    search_fields = ('nombre', 'evaluacion__nombre')
    readonly_fields = ('fecha_creacion', 'fecha_modificacion')
    ordering = ('-fecha_creacion',)
    inlines = [ObjetivoAprendizajeInline]
    
    fieldsets = (
        ('Información Básica', {
            'fields': ('evaluacion', 'nombre')
        }),
        ('Estado', {
            'fields': ('activa', 'creado_por')
        }),
        ('Fechas', {
            'fields': ('fecha_creacion', 'fecha_modificacion'),
            'classes': ('collapse',)
        }),
    )

class ObjetivoAprendizajeAdmin(admin.ModelAdmin):
    list_display = ('nombre', 'rubrica', 'activo', 'fecha_creacion')
    list_filter = ('activo', 'rubrica__evaluacion__curso')
    search_fields = ('nombre', 'descripcion', 'rubrica__nombre')
    ordering = ('rubrica',)
    
    fieldsets = (
        ('Información Básica', {
            'fields': ('rubrica', 'nombre', 'descripcion', 'activo')
        }),
        ('Fechas', {
            'fields': ('fecha_creacion', 'fecha_modificacion'),
            'classes': ('collapse',)
        }),
    )
    readonly_fields = ('fecha_creacion', 'fecha_modificacion')

admin.site.register(Rubrica, RubricaAdmin)
admin.site.register(CriterioRubrica, CriterioRubricaAdmin)
admin.site.register(ObjetivoAprendizaje, ObjetivoAprendizajeAdmin)
