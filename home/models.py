import uuid
from django.db import models
from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.contrib.postgres.fields import JSONField
import os

class CustomUser(AbstractUser):
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    company_name = models.CharField(max_length=100, blank=True, null=True)
    company_rut = models.CharField(max_length=12, blank=True, null=True)  # Consider adding specific validation
    company_address = models.CharField(max_length=255, blank=True, null=True)
    admin_name = models.CharField(max_length=100, blank=True, null=True)
    profile_photo = models.ImageField(upload_to='profile_photos/', blank=True, null=True, help_text="Foto de perfil del usuario")
    
    def __str__(self):
        """Retorna el nombre completo del usuario o el username si no tiene nombre"""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        elif self.first_name:
            return self.first_name
        elif self.last_name:
            return self.last_name
        else:
            return self.username

class Service(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()
    category = models.CharField(max_length=50)
    html_block = models.TextField(blank=True, null=True)
    image = models.ImageField(upload_to='service_images/', blank=True, null=True)

    def __str__(self):
        return self.name

class ServiceProvision(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='service_provisions')
    service = models.ForeignKey(Service, on_delete=models.CASCADE, related_name='provisions')
    start_date = models.DateField()
    end_date = models.DateField(null=True, blank=True)
    custom_url = models.URLField(blank=True, null=True)
    configurations = models.JSONField(default=dict)  # Using PostgreSQL JSON field for dynamic configurations

    def __str__(self):
        return f'{self.user.username} - {self.service.name}'

class Billing(models.Model):
    provision = models.ForeignKey(ServiceProvision, on_delete=models.CASCADE, related_name='billings')
    date = models.DateField()
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=3)
    billing_type = models.CharField(max_length=50)
    status = models.CharField(max_length=50)
    payment_due_date = models.DateField()

    def __str__(self):
        return f'Billing for {self.provision.user.username}: {self.amount} {self.currency}'

class Notification(models.Model):
    provision = models.ForeignKey(ServiceProvision, on_delete=models.CASCADE, related_name='notifications')
    timestamp = models.DateTimeField()
    message = models.TextField()

    def __str__(self):
        return f'Notification for {self.provision.user.username} - {self.message}'

class RegistrationLink(models.Model):
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    creator = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='registration_links')
    created_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)

    def __str__(self):
        return str(self.uuid)

class Comment(models.Model):
    post = models.ForeignKey('Post', on_delete=models.CASCADE, related_name='comments')
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['created_at']

    def __str__(self):
        return f'Comentario de {self.author.username} en {self.post.title}'


class Post(models.Model):
    CATEGORY_CHOICES = [
        ('general', 'General'),
        ('tecnologia', 'Tecnología'),
        ('negocios', 'Negocios'),
        ('economia', 'Economía'),
    ]
    
    curso = models.ForeignKey('Curso', on_delete=models.CASCADE, related_name='posts', null=True, blank=True)
    title = models.CharField(max_length=200)
    content = models.TextField()
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, default='general')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    views = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.title

    def get_comment_count(self):
        return self.comments.filter(is_active=True).count()

    def get_view_count(self):
        return self.views

class Curso(models.Model):
    nombre = models.CharField(max_length=100)
    codigo = models.CharField(max_length=100, unique=True)
    descripcion = models.TextField(blank=True, null=True)
    fecha_inicio = models.DateField(blank=True, null=True)
    fecha_fin = models.DateField(blank=True, null=True)
    activo = models.BooleanField(default=True)
    precio = models.DecimalField(max_digits=10, decimal_places=0, blank=True, null=True, help_text="Precio del curso")
    dias_plazo_pago = models.IntegerField(help_text="Días de plazo para realizar el pago")

    # Nuevos campos para la página de detalle
    docente_nombre = models.CharField(max_length=100, blank=True, null=True)
    docente_titulos = models.TextField(blank=True, null=True, help_text="Títulos y certificaciones del docente")
    docente_trayectoria = models.TextField(blank=True, null=True, help_text="Experiencia y trayectoria profesional del docente")
    docente_foto = models.ImageField(upload_to='docentes/', blank=True, null=True)
    
    requisitos = models.TextField(blank=True, null=True, help_text="Requisitos previos para el curso")
    contenido = models.TextField(blank=True, null=True, help_text="Contenido del curso")
    
    # Información adicional del curso
    duracion = models.CharField(max_length=50, blank=True, null=True, help_text="Duración del curso (ej: 8 semanas)")
    modalidad = models.CharField(max_length=50, blank=True, null=True, help_text="Modalidad del curso (ej: Online, Presencial, Híbrido)")
    nivel = models.CharField(max_length=50, blank=True, null=True, help_text="Nivel del curso (ej: Básico, Intermedio, Avanzado)")
    
    # Archivos del curso
    archivo_introductorio = models.FileField(upload_to='cursos/material_introductorio/', blank=True, null=True)
    
    # Relación con Asignatura
    asignatura = models.ForeignKey('Asignatura', on_delete=models.SET_NULL, blank=True, null=True, related_name='cursos', help_text="Asignatura a la que pertenece este curso")

    def __str__(self):
        return self.nombre
    
    def get_proximas_videollamadas(self):
        """Obtiene las próximas videollamadas programadas para este curso"""
        from django.utils import timezone
        from datetime import datetime, timedelta
        
        ahora = timezone.localtime(timezone.now())
        fecha_actual = ahora.date()
        dia_actual = ahora.weekday()
        hora_actual = ahora.time()
        
        # Verificar que la fecha actual esté dentro del rango del curso
        if self.fecha_inicio and fecha_actual < self.fecha_inicio:
            return []  # El curso aún no ha comenzado
        
        if self.fecha_fin and fecha_actual > self.fecha_fin:
            return []  # El curso ya ha terminado
        
        proximas = []
        for videollamada in self.videollamadas.filter(activa=True):
            # Si es hoy y aún no ha terminado
            if videollamada.dia_semana == dia_actual and videollamada.hora_fin > hora_actual:
                proximas.append(videollamada)
            # Si es un día futuro
            elif videollamada.dia_semana > dia_actual:
                proximas.append(videollamada)
            # Si es el próximo lunes (después del domingo)
            elif videollamada.dia_semana < dia_actual:
                proximas.append(videollamada)
        
        # Ordenar por día y hora
        return sorted(proximas, key=lambda x: (x.dia_semana, x.hora_inicio))

# Relación muchos a muchos entre usuario y curso
CustomUser.add_to_class('cursos', models.ManyToManyField('Curso', related_name='usuarios', blank=True))

class BlogPost(models.Model):
    CATEGORY_CHOICES = [
        ('noticias', 'Noticias'),
        ('tutoriales', 'Tutoriales'),
        ('casos_exito', 'Casos de Éxito'),
        ('consejos', 'Consejos'),
        ('eventos', 'Eventos'),
    ]
    
    title = models.CharField(max_length=200)
    content = models.TextField()
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, default='noticias')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    views = models.PositiveIntegerField(default=0)
    featured_image = models.ImageField(upload_to='blog_images/', blank=True, null=True)
    excerpt = models.TextField(max_length=300, blank=True, null=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.title

    def get_view_count(self):
        return self.views

    def get_excerpt(self):
        if self.excerpt:
            return self.excerpt
        return self.content[:200] + "..." if len(self.content) > 200 else self.content

class Videollamada(models.Model):
    DIAS_SEMANA = [
        (0, 'Lunes'),
        (1, 'Martes'),
        (2, 'Miércoles'),
        (3, 'Jueves'),
        (4, 'Viernes'),
        (5, 'Sábado'),
        (6, 'Domingo'),
    ]
    
    curso = models.ForeignKey(Curso, on_delete=models.CASCADE, related_name='videollamadas')
    dia_semana = models.IntegerField(choices=DIAS_SEMANA, help_text="Día de la semana para la videollamada")
    hora_inicio = models.TimeField(help_text="Hora de inicio de la videollamada")
    hora_fin = models.TimeField(help_text="Hora de fin de la videollamada")
    link_videollamada = models.URLField(help_text="Enlace de la videollamada", blank=True, null=True)
    activa = models.BooleanField(default=True, help_text="Indica si esta videollamada está activa")
    descripcion = models.CharField(max_length=200, blank=True, null=True, help_text="Descripción opcional de la videollamada")
    
    class Meta:
        ordering = ['dia_semana', 'hora_inicio']
        unique_together = ['curso', 'dia_semana', 'hora_inicio']
    
    def __str__(self):
        return f"{self.curso.nombre} - {self.get_dia_semana_display()} {self.hora_inicio}"
    
    def esta_activa_ahora(self):
        """Verifica si la videollamada está activa en el momento actual"""
        from django.utils import timezone
        from datetime import datetime, time
        import logging
        import traceback
        
        logger = logging.getLogger('home.models')
        
        try:
            logger.debug(f"Iniciando esta_activa_ahora para videollamada {self.id}")
            
            # Verificar que los campos necesarios existan
            if not hasattr(self, 'activa'):
                logger.error(f"Videollamada {self.id} no tiene campo 'activa'")
                return False
                
            if not hasattr(self, 'dia_semana'):
                logger.error(f"Videollamada {self.id} no tiene campo 'dia_semana'")
                return False
                
            if not hasattr(self, 'hora_inicio'):
                logger.error(f"Videollamada {self.id} no tiene campo 'hora_inicio'")
                return False
                
            if not hasattr(self, 'hora_fin'):
                logger.error(f"Videollamada {self.id} no tiene campo 'hora_fin'")
                return False
            
            # Usar la zona horaria configurada en Django
            logger.debug("Obteniendo tiempo actual...")
            ahora = timezone.localtime(timezone.now())
            fecha_actual = ahora.date()
            hora_actual = ahora.time()
            dia_actual = ahora.weekday()
            
            logger.debug(f"Videollamada {self.id}: activa={self.activa}, dia_semana={self.dia_semana}, dia_actual={dia_actual}, hora_inicio={self.hora_inicio}, hora_fin={self.hora_fin}, hora_actual={hora_actual}")
            
            # Verificar que la fecha actual esté dentro del rango del curso
            if self.curso.fecha_inicio and fecha_actual < self.curso.fecha_inicio:
                logger.debug(f"Videollamada {self.id}: El curso aún no ha comenzado (fecha_actual={fecha_actual}, fecha_inicio_curso={self.curso.fecha_inicio})")
                return False
            
            if self.curso.fecha_fin and fecha_actual > self.curso.fecha_fin:
                logger.debug(f"Videollamada {self.id}: El curso ya ha terminado (fecha_actual={fecha_actual}, fecha_fin_curso={self.curso.fecha_fin})")
                return False
            
            # Verificar cada condición por separado
            condicion_activa = self.activa
            condicion_dia = dia_actual == self.dia_semana
            condicion_hora = self.hora_inicio <= hora_actual <= self.hora_fin
            
            logger.debug(f"Condiciones: activa={condicion_activa}, dia={condicion_dia}, hora={condicion_hora}")
            
            resultado = (condicion_activa and condicion_dia and condicion_hora)
            
            logger.debug(f"Videollamada {self.id} esta_activa_ahora: {resultado}")
            return resultado
            
        except Exception as e:
            logger.error(f"Error en esta_activa_ahora para videollamada {self.id}: {str(e)}")
            logger.error(f"Tipo de error: {type(e).__name__}")
            logger.error(f"Traceback completo: {traceback.format_exc()}")
            return False
    
    def clean(self):
        """Validación personalizada del modelo"""
        from django.core.exceptions import ValidationError
        
        # Verificar que la hora de fin sea posterior a la hora de inicio
        if self.hora_inicio and self.hora_fin and self.hora_inicio >= self.hora_fin:
            raise ValidationError('La hora de fin debe ser posterior a la hora de inicio.')
        
        # Verificar que si está activa, tenga enlace configurado
        if self.activa and not self.link_videollamada:
            raise ValidationError('Una videollamada activa debe tener un enlace configurado.')
    
    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)

class InscripcionCurso(models.Model):
    ESTADO_CHOICES = [
        ('pendiente', 'Pendiente de Pago'),
        ('pagado', 'Pagado'),
        ('cancelado', 'Cancelado'),
    ]
    
    nombre_interesado = models.CharField(max_length=100)
    nombre_empresa = models.CharField(max_length=100)
    telefono_contacto = models.CharField(max_length=15, blank=True, null=True)
    correo_contacto = models.EmailField()
    curso = models.ForeignKey(Curso, on_delete=models.CASCADE, related_name='inscripciones')
    fecha_solicitud = models.DateTimeField(auto_now_add=True)
    fecha_pago = models.DateTimeField(blank=True, null=True)
    estado = models.CharField(max_length=20, choices=ESTADO_CHOICES, default='pendiente')
    usuario_creado = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, blank=True, null=True, related_name='inscripciones_creadas')
    observaciones = models.TextField(blank=True, null=True)
    
    # Campos para tracking de errores en el proceso de pago
    error_creacion_correo = models.TextField(blank=True, null=True, help_text="Error al crear dirección de correo")
    error_envio_bienvenida = models.TextField(blank=True, null=True, help_text="Error al enviar correo de bienvenida")
    fecha_ultimo_intento = models.DateTimeField(blank=True, null=True, help_text="Fecha del último intento de procesamiento")
    intentos_procesamiento = models.PositiveIntegerField(default=0, help_text="Número de intentos de procesamiento")
    password_temp = models.CharField(max_length=100, blank=True, null=True, help_text="Contraseña temporal para usuarios nuevos")
    
    class Meta:
        ordering = ['-fecha_solicitud']
        verbose_name = 'Inscripción a Curso'
        verbose_name_plural = 'Inscripciones a Cursos'
    
    def __str__(self):
        return f"{self.nombre_interesado} - {self.curso.nombre} ({self.get_estado_display()})"
    
    def marcar_como_pagado(self):
        """Marca la inscripción como pagada y crea el usuario o reutiliza uno existente"""
        from django.utils import timezone
        import secrets
        import string
        
        if self.estado == 'pendiente':
            self.estado = 'pagado'
            self.fecha_pago = timezone.now()
            
            # Generar username basado en el nombre
            username = f"{self.nombre_interesado.lower().replace(' ', '_')}"
            
            # Verificar si ya existe un usuario con el mismo username
            user_existente = CustomUser.objects.filter(username=username).first()
            
            if user_existente:
                # Usar usuario existente
                user = user_existente
                password_temp = None
                
                # Verificar si el usuario ya tiene acceso al curso
                if not user.cursos.filter(id=self.curso.id).exists():
                    # Agregar el curso al usuario existente
                    user.cursos.add(self.curso)
                
                # Actualizar información del usuario si es necesario
                if not user.first_name and self.nombre_interesado.split():
                    user.first_name = self.nombre_interesado.split()[0]
                if not user.last_name and len(self.nombre_interesado.split()) > 1:
                    user.last_name = ' '.join(self.nombre_interesado.split()[1:])
                if not user.phone_number and self.telefono_contacto:
                    user.phone_number = self.telefono_contacto
                if not user.company_name and self.nombre_empresa:
                    user.company_name = self.nombre_empresa
                if not user.email and self.correo_contacto:
                    user.email = self.correo_contacto
                
                user.save()
                
            else:
                # Crear nuevo usuario
                # Generar contraseña temporal
                alphabet = string.ascii_letters + string.digits
                password_temp = ''.join(secrets.choice(alphabet) for i in range(12))
                
                # Asegurar que el username sea único
                counter = 1
                original_username = username
                while CustomUser.objects.filter(username=username).exists():
                    username = f"{original_username}_{counter}"
                    counter += 1
                
                user = CustomUser.objects.create_user(
                    username=username,
                    email=self.correo_contacto,
                    password=password_temp,
                    first_name=self.nombre_interesado.split()[0] if self.nombre_interesado.split() else '',
                    last_name=' '.join(self.nombre_interesado.split()[1:]) if len(self.nombre_interesado.split()) > 1 else '',
                    phone_number=self.telefono_contacto,
                    company_name=self.nombre_empresa,
                    is_active=True
                )
                
                # Asignar el curso al usuario
                user.cursos.add(self.curso)
            
            self.usuario_creado = user
            self.password_temp = password_temp
            self.save()
            
            return user, password_temp
        
        return None, None

class Evaluacion(models.Model):
    TIPO_CHOICES = [
        ('tarea', 'Tarea'),
        ('examen', 'Examen'),
        ('proyecto', 'Proyecto'),
        ('participacion', 'Participación'),
        ('trabajo_practico', 'Trabajo Práctico'),
        ('presentacion', 'Presentación'),
        ('otro', 'Otro'),
    ]
    
    curso = models.ForeignKey(Curso, on_delete=models.CASCADE, related_name='evaluaciones')
    tipo = models.CharField(max_length=20, choices=TIPO_CHOICES, help_text="Tipo de evaluación")
    nombre = models.CharField(max_length=200, help_text="Nombre de la evaluación")
    fecha_inicio = models.DateField(help_text="Fecha de inicio de la evaluación", blank=True, null=True)
    fecha_fin = models.DateField(help_text="Fecha de fin de la evaluación", blank=True, null=True)
    nota_maxima = models.DecimalField(max_digits=5, decimal_places=2, help_text="Nota máxima posible")
    ponderacion = models.DecimalField(max_digits=5, decimal_places=2, help_text="Ponderación en porcentaje")
    descripcion = models.TextField(blank=True, null=True, help_text="Descripción de la evaluación")
    fecha_creacion = models.DateTimeField(auto_now_add=True)
    fecha_modificacion = models.DateTimeField(auto_now=True)
    activa = models.BooleanField(default=True, help_text="Indica si la evaluación está activa")
    creado_por = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='evaluaciones_creadas', blank=True, null=True)
    
    class Meta:
        ordering = ['-fecha_inicio', '-fecha_creacion']
        verbose_name = 'Evaluación'
        verbose_name_plural = 'Evaluaciones'
        unique_together = ['curso', 'nombre']
    
    def __str__(self):
        return f"{self.nombre} - {self.curso.nombre}"
    
    def get_calificaciones_count(self):
        """Retorna el número de calificaciones registradas para esta evaluación"""
        return self.calificaciones.count()
    
    def get_promedio(self):
        """Retorna el promedio de las calificaciones de esta evaluación"""
        calificaciones = self.calificaciones.filter(nota__isnull=False)
        if calificaciones.exists():
            return calificaciones.aggregate(models.Avg('nota'))['nota__avg']
        return None

class Calificacion(models.Model):
    evaluacion = models.ForeignKey(Evaluacion, on_delete=models.CASCADE, related_name='calificaciones')
    estudiante = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='calificaciones')
    nota = models.DecimalField(max_digits=5, decimal_places=2, blank=True, null=True, help_text="Nota obtenida")
    retroalimentacion = models.TextField(blank=True, null=True, help_text="Retroalimentación para el estudiante")
    calificado_por = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='calificaciones_asignadas')
    fecha_calificacion = models.DateTimeField(auto_now_add=True)
    fecha_modificacion = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-fecha_calificacion']
        verbose_name = 'Calificación'
        verbose_name_plural = 'Calificaciones'
        unique_together = ['evaluacion', 'estudiante']
    
    def __str__(self):
        return f"{self.estudiante.get_full_name()} - {self.evaluacion.nombre}: {self.nota}"
    
    def get_porcentaje_obtenido(self):
        """Retorna el porcentaje obtenido respecto a la nota máxima"""
        if self.nota and self.evaluacion.nota_maxima:
            return (self.nota / self.evaluacion.nota_maxima) * 100
        return None
    
    def get_nota_ponderada(self):
        """Retorna la nota ponderada según la ponderación de la evaluación"""
        if self.nota and self.evaluacion.ponderacion:
            return (self.nota / self.evaluacion.nota_maxima) * self.evaluacion.ponderacion
        return None

class Rubrica(models.Model):
    """
    Modelo para rúbricas de evaluación
    """
    evaluacion = models.OneToOneField(Evaluacion, on_delete=models.CASCADE, related_name='rubrica')
    nombre = models.CharField(max_length=200, help_text="Nombre de la rúbrica")
    fecha_creacion = models.DateTimeField(auto_now_add=True)
    fecha_modificacion = models.DateTimeField(auto_now=True)
    activa = models.BooleanField(default=True, help_text="Indica si la rúbrica está activa")
    creado_por = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='rubricas_creadas', blank=True, null=True)
    
    class Meta:
        ordering = ['-fecha_creacion']
        verbose_name = 'Rúbrica'
        verbose_name_plural = 'Rúbricas'
    
    def __str__(self):
        return f"{self.nombre} - {self.evaluacion.nombre}"
    
    def get_criterios_count(self):
        """Retorna el número de criterios de la rúbrica"""
        return self.criterios.count()
    
    def get_puntaje_total(self):
        """Retorna el puntaje total de la rúbrica"""
        return self.criterios.aggregate(total=models.Sum('puntaje'))['total'] or 0

class ObjetivoAprendizaje(models.Model):
    """
    Modelo para objetivos de aprendizaje que pueden estar asociados a múltiples criterios de rúbrica
    """
    rubrica = models.ForeignKey(Rubrica, on_delete=models.CASCADE, related_name='objetivos_aprendizaje')
    nombre = models.CharField(max_length=200, help_text="Nombre del objetivo de aprendizaje")
    descripcion = models.TextField(help_text="Descripción detallada del objetivo")
    orden = models.PositiveIntegerField(default=0, help_text="Orden de aparición del objetivo")
    activo = models.BooleanField(default=True, help_text="Indica si el objetivo está activo")
    fecha_creacion = models.DateTimeField(auto_now_add=True)
    fecha_modificacion = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['orden', 'nombre']
        verbose_name = 'Objetivo de Aprendizaje'
        verbose_name_plural = 'Objetivos de Aprendizaje'
        unique_together = ['rubrica', 'nombre']
    
    def __str__(self):
        return f"{self.nombre} - {self.rubrica.nombre}"
    
    def get_criterios_count(self):
        """Retorna el número de criterios asociados a este objetivo"""
        return self.criterios.count()

class CriterioRubrica(models.Model):
    """
    Modelo para criterios de una rúbrica
    """
    rubrica = models.ForeignKey(Rubrica, on_delete=models.CASCADE, related_name='criterios')
    nombre = models.CharField(max_length=200, help_text="Nombre del criterio")
    objetivo = models.TextField(help_text="Objetivo del criterio")
    puntaje = models.DecimalField(max_digits=5, decimal_places=2, default=0, help_text="Puntaje máximo para este criterio")
    orden = models.PositiveIntegerField(default=0, help_text="Orden de aparición del criterio")
    objetivo_aprendizaje = models.ForeignKey(
        ObjetivoAprendizaje, 
        on_delete=models.SET_NULL, 
        blank=True, 
        null=True, 
        related_name='criterios',
        help_text="Objetivo de aprendizaje asociado a este criterio"
    )
    
    class Meta:
        ordering = ['orden', 'nombre']
        verbose_name = 'Criterio de Rúbrica'
        verbose_name_plural = 'Criterios de Rúbrica'
    
    def __str__(self):
        return f"{self.nombre} - {self.rubrica.nombre}"

class Esperable(models.Model):
    """
    Modelo para esperables (expectativas) de un criterio
    """
    criterio = models.ForeignKey(CriterioRubrica, on_delete=models.CASCADE, related_name='esperables')
    nivel = models.CharField(max_length=100, help_text="Nivel de desempeño (ej: Aceptable, Bueno, Excelente)")
    descripcion = models.TextField(help_text="Descripción de la expectativa para este nivel")
    puntaje = models.DecimalField(max_digits=5, decimal_places=2, default=0, help_text="Puntaje asociado a este esperable")
    orden = models.PositiveIntegerField(default=0, help_text="Orden de aparición del esperable")
    
    class Meta:
        ordering = ['orden', 'nivel']
        verbose_name = 'Esperable'
        verbose_name_plural = 'Esperables'
    
    def __str__(self):
        return f"{self.nivel} - {self.criterio.nombre} ({self.puntaje} pts)"

class ResultadoRubrica(models.Model):
    """
    Modelo para almacenar los resultados de aplicar una rúbrica a un estudiante
    """
    rubrica = models.ForeignKey(Rubrica, on_delete=models.CASCADE, related_name='resultados')
    estudiante = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='resultados_rubrica')
    evaluador = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='evaluaciones_realizadas')
    fecha_evaluacion = models.DateTimeField(auto_now_add=True)
    fecha_modificacion = models.DateTimeField(auto_now=True)
    comentarios_generales = models.TextField(blank=True, null=True, help_text="Comentarios generales de la evaluación")
    puntaje_total = models.DecimalField(max_digits=5, decimal_places=2, blank=True, null=True, help_text="Puntaje total obtenido")
    nota_final = models.DecimalField(max_digits=5, decimal_places=2, blank=True, null=True, help_text="Nota final calculada")
    
    class Meta:
        ordering = ['-fecha_evaluacion']
        verbose_name = 'Resultado de Rúbrica'
        verbose_name_plural = 'Resultados de Rúbricas'
        unique_together = ['rubrica', 'estudiante']
    
    def __str__(self):
        return f"{self.estudiante.get_full_name()} - {self.rubrica.nombre}: {self.puntaje_total}"
    
    def calcular_puntaje_total(self):
        """Calcula el puntaje total basado en los puntajes de cada criterio"""
        puntajes = self.puntajes_criterios.values_list('puntaje_obtenido', flat=True)
        total = sum(puntajes) if puntajes else 0
        # Actualizar el campo puntaje_total
        self.puntaje_total = total
        self.save(update_fields=['puntaje_total'])
        return total
    
    def calcular_nota_final(self):
        """Calcula la nota final basada en el puntaje total y la nota máxima de la evaluación"""
        if self.puntaje_total and self.rubrica.evaluacion.nota_maxima:
            puntaje_maximo_rubrica = self.rubrica.get_puntaje_total()
            if puntaje_maximo_rubrica > 0:
                return (self.puntaje_total / puntaje_maximo_rubrica) * self.rubrica.evaluacion.nota_maxima
        return None

class PuntajeCriterio(models.Model):
    """
    Modelo para almacenar el puntaje obtenido en cada criterio de una evaluación
    """
    resultado_rubrica = models.ForeignKey(ResultadoRubrica, on_delete=models.CASCADE, related_name='puntajes_criterios')
    criterio = models.ForeignKey(CriterioRubrica, on_delete=models.CASCADE, related_name='puntajes')
    esperable_seleccionado = models.ForeignKey(Esperable, on_delete=models.CASCADE, related_name='puntajes_asignados', blank=True, null=True)
    puntaje_obtenido = models.DecimalField(max_digits=5, decimal_places=2, help_text="Puntaje obtenido en este criterio")
    comentarios = models.TextField(blank=True, null=True, help_text="Comentarios específicos para este criterio")
    
    class Meta:
        ordering = ['criterio__orden']
        verbose_name = 'Puntaje de Criterio'
        verbose_name_plural = 'Puntajes de Criterios'
        unique_together = ['resultado_rubrica', 'criterio']
    
    def __str__(self):
        return f"{self.criterio.nombre} - {self.puntaje_obtenido}"
    
    def get_puntajes_esperables(self, resultado_rubrica, criterio):
        return self.resultado_rubrica.puntajes_criterios.filter(resultado_rubrica=resultado_rubrica, criterio=criterio)
    
    
class Entrega(models.Model):
    ESTADO_CHOICES = [
        ('pendiente', 'Pendiente'),
        ('entregado', 'Entregado'),
        ('tardio', 'Tardío'),
        ('rechazado', 'Rechazado'),
        ('aprobado', 'Aprobado'),
    ]
    
    evaluacion = models.ForeignKey(Evaluacion, on_delete=models.CASCADE, related_name='entregas')
    estudiante = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='entregas')
    archivo = models.FileField(upload_to='entregas/', help_text="Archivo de la entrega")
    comentario = models.TextField(blank=True, null=True, help_text="Comentario opcional del estudiante")
    fecha_entrega = models.DateTimeField(auto_now_add=True, help_text="Fecha y hora de entrega")
    estado = models.CharField(max_length=20, choices=ESTADO_CHOICES, default='pendiente', help_text="Estado de la entrega")
    calificacion = models.OneToOneField(Calificacion, on_delete=models.CASCADE, related_name='entrega', blank=True, null=True, help_text="Calificación asociada a esta entrega")
    revisado_por = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, blank=True, null=True, related_name='entregas_revisadas')
    fecha_revision = models.DateTimeField(blank=True, null=True, help_text="Fecha de revisión")
    comentario_revisor = models.TextField(blank=True, null=True, help_text="Comentario del revisor")
    
    class Meta:
        ordering = ['-fecha_entrega']
        verbose_name = 'Entrega'
        verbose_name_plural = 'Entregas'
        unique_together = ['evaluacion', 'estudiante']
    
    def __str__(self):
        return f"{self.estudiante.get_full_name()} - {self.evaluacion.nombre}"
    
    def get_nombre_archivo(self):
        """Retorna el nombre del archivo sin la ruta"""
        if self.archivo:
            return self.archivo.name.split('/')[-1]
        return "Sin archivo"
    
    def get_tamano_archivo(self):
        """Retorna el tamaño del archivo en formato legible"""
        if self.archivo and hasattr(self.archivo, 'size'):
            size = self.archivo.size
            for unit in ['B', 'KB', 'MB', 'GB']:
                if size < 1024.0:
                    return f"{size:.1f} {unit}"
                size /= 1024.0
            return f"{size:.1f} TB"
        return "N/A"
    
    def es_tardia(self):
        """Verifica si la entrega es tardía"""
        from django.utils import timezone
        if self.evaluacion.fecha_fin:
            return self.fecha_entrega.date() > self.evaluacion.fecha_fin
        return False
    
    def puede_entregar(self):
        """Verifica si el estudiante puede entregar"""
        from django.utils import timezone
        ahora = timezone.now()
        
        # Verificar que la evaluación esté activa
        if not self.evaluacion.activa:
            return False
        
        # Verificar fechas
        if self.evaluacion.fecha_inicio and ahora.date() < self.evaluacion.fecha_inicio:
            return False
        
        if self.evaluacion.fecha_fin and ahora.date() > self.evaluacion.fecha_fin:
            return False
        
        return True

class TicketSoporte(models.Model):
    """
    Modelo para tickets de soporte al estudiante
    """
    ESTADO_CHOICES = [
        ('abierto', 'Abierto'),
        ('en_proceso', 'En Proceso'),
        ('resuelto', 'Resuelto'),
        ('cerrado', 'Cerrado'),
    ]
    
    PRIORIDAD_CHOICES = [
        ('baja', 'Baja'),
        ('media', 'Media'),
        ('alta', 'Alta'),
        ('urgente', 'Urgente'),
    ]
    
    # Campos principales
    titulo = models.CharField(max_length=200, help_text="Título del ticket")
    descripcion = models.TextField(help_text="Descripción detallada del problema")
    
    # Clasificación
    clasificacion = models.CharField(max_length=100, help_text="Clasificación principal del ticket")
    subclasificacion = models.CharField(max_length=100, help_text="Subclasificación del ticket")
    
    # Estado y prioridad
    estado = models.CharField(max_length=20, choices=ESTADO_CHOICES, default='abierto')
    prioridad = models.CharField(max_length=20, choices=PRIORIDAD_CHOICES, default='media')
    
    # Usuario y curso
    usuario = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='tickets_soporte')
    curso = models.ForeignKey(Curso, on_delete=models.CASCADE, related_name='tickets_soporte')
    
    # Fechas
    fecha_creacion = models.DateTimeField(auto_now_add=True)
    fecha_actualizacion = models.DateTimeField(auto_now=True)
    fecha_resolucion = models.DateTimeField(blank=True, null=True)
    
    # Asignación
    asignado_a = models.ForeignKey(
        CustomUser, 
        on_delete=models.SET_NULL, 
        blank=True, 
        null=True, 
        related_name='tickets_asignados',
        help_text="Usuario admin/staff asignado al ticket"
    )
    
    class Meta:
        ordering = ['-fecha_creacion']
        verbose_name = 'Ticket de Soporte'
        verbose_name_plural = 'Tickets de Soporte'
    
    def __str__(self):
        return f"Ticket #{self.id} - {self.titulo}"
    
    def get_ultimo_comentario(self):
        """Retorna el último comentario del ticket"""
        return self.comentarios.order_by('-fecha_creacion').first()
    
    def get_comentarios_count(self):
        """Retorna el número de comentarios del ticket"""
        return self.comentarios.count()
    
    def puede_comentar(self, usuario):
        """Verifica si un usuario puede comentar en el ticket"""
        # Si el ticket está resuelto, solo los superusuarios pueden comentar
        if self.estado == 'resuelto':
            return usuario.is_superuser
        
        # Para otros estados, permitir al usuario que creó el ticket, staff y superusuarios
        return usuario == self.usuario or usuario.is_staff or usuario.is_superuser


class ComentarioTicket(models.Model):
    """
    Modelo para comentarios en tickets de soporte
    """
    ticket = models.ForeignKey(TicketSoporte, on_delete=models.CASCADE, related_name='comentarios')
    autor = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='comentarios_tickets')
    contenido = models.TextField(help_text="Contenido del comentario")
    fecha_creacion = models.DateTimeField(auto_now_add=True)
    fecha_actualizacion = models.DateTimeField(auto_now=True)
    
    # Para comentarios internos del staff
    es_interno = models.BooleanField(
        default=False, 
        help_text="Si es True, solo lo ven usuarios admin/staff"
    )
    
    class Meta:
        ordering = ['fecha_creacion']
        verbose_name = 'Comentario de Ticket'
        verbose_name_plural = 'Comentarios de Tickets'
    
    def __str__(self):
        return f"Comentario de {self.autor.username} en Ticket #{self.ticket.id}"
    
    def puede_ver(self, usuario):
        """Verifica si un usuario puede ver este comentario"""
        if not self.es_interno:
            return True
        return usuario.is_staff or usuario.is_superuser


class ClasificacionTicket(models.Model):
    """
    Modelo para configurar las clasificaciones de tickets
    """
    nombre = models.CharField(max_length=100, unique=True, help_text="Nombre de la clasificación")
    descripcion = models.TextField(blank=True, null=True, help_text="Descripción de la clasificación")
    activa = models.BooleanField(default=True, help_text="Si la clasificación está activa")
    
    class Meta:
        ordering = ['nombre']
        verbose_name = 'Clasificación de Ticket'
        verbose_name_plural = 'Clasificaciones de Tickets'
    
    def __str__(self):
        return self.nombre


class SubclasificacionTicket(models.Model):
    """
    Modelo para configurar las subclasificaciones de tickets
    """
    clasificacion = models.ForeignKey(ClasificacionTicket, on_delete=models.CASCADE, related_name='subclasificaciones')
    nombre = models.CharField(max_length=100, help_text="Nombre de la subclasificación")
    descripcion = models.TextField(blank=True, null=True, help_text="Descripción de la subclasificación")
    activa = models.BooleanField(default=True, help_text="Si la subclasificación está activa")
    
    class Meta:
        ordering = ['clasificacion', 'nombre']
        verbose_name = 'Subclasificación de Ticket'
        verbose_name_plural = 'Subclasificaciones de Tickets'
        unique_together = ['clasificacion', 'nombre']
    
    def __str__(self):
        return f"{self.clasificacion.nombre} - {self.nombre}"
    
class Recurso(models.Model):
    """
    Modelo para recursos de aprendizaje asociados a evaluaciones
    """
    TIPO_CHOICES = [
        ('documento', 'Documento'),
        ('video', 'Video'),
        ('presentacion', 'Presentación'),
        ('enlace', 'Enlace'),
        ('imagen', 'Imagen'),
        ('audio', 'Audio'),
        ('otro', 'Otro'),
    ]
    
    evaluacion = models.ForeignKey(Evaluacion, on_delete=models.CASCADE, related_name='recursos')
    nombre = models.CharField(max_length=200, help_text="Nombre del recurso")
    descripcion = models.TextField(help_text="Descripción del recurso")
    tipo = models.CharField(max_length=20, choices=TIPO_CHOICES, help_text="Tipo de recurso")
    archivo_adjunto = models.FileField(upload_to='recursos/', blank=True, null=True, help_text="Archivo adjunto del recurso")
    enlace_externo = models.URLField(blank=True, null=True, help_text="Enlace externo (si aplica)")
    fecha_creacion = models.DateTimeField(auto_now_add=True)
    fecha_modificacion = models.DateTimeField(auto_now=True)
    activo = models.BooleanField(default=True, help_text="Indica si el recurso está activo")
    creado_por = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='recursos_creados', blank=True, null=True)
    
    class Meta:
        ordering = ['-fecha_creacion']
        verbose_name = 'Recurso'
        verbose_name_plural = 'Recursos'
    
    def __str__(self):
        return f"{self.nombre} - {self.evaluacion.nombre}"
    
    def get_tipo_display_name(self):
        """Retorna el nombre legible del tipo de recurso"""
        return dict(self.TIPO_CHOICES).get(self.tipo, self.tipo)
    
    def get_icono_tipo(self):
        """Retorna el ícono correspondiente al tipo de recurso"""
        iconos = {
            'documento': 'fas fa-file-alt',
            'video': 'fas fa-video',
            'presentacion': 'fas fa-presentation',
            'enlace': 'fas fa-link',
            'imagen': 'fas fa-image',
            'audio': 'fas fa-music',
            'otro': 'fas fa-file',
        }
        return iconos.get(self.tipo, 'fas fa-file')
    
    def tiene_archivo(self):
        """Verifica si el recurso tiene un archivo adjunto"""
        return bool(self.archivo_adjunto)
    
    def tiene_enlace(self):
        """Verifica si el recurso tiene un enlace externo"""
        return bool(self.enlace_externo)
    
    def get_nombre_archivo(self):
        """Retorna el nombre del archivo adjunto"""
        if self.archivo_adjunto:
            return os.path.basename(self.archivo_adjunto.name)
        return None
    
    def get_tamano_archivo(self):
        """Retorna el tamaño del archivo en formato legible"""
        if self.archivo_adjunto and hasattr(self.archivo_adjunto, 'size'):
            size = self.archivo_adjunto.size
            for unit in ['B', 'KB', 'MB', 'GB']:
                if size < 1024.0:
                    return f"{size:.1f} {unit}"
                size /= 1024.0
            return f"{size:.1f} TB"
        return None

class Asignatura(models.Model):
    """
    Modelo para agrupar cursos relacionados. Una asignatura puede tener múltiples cursos.
    Permite copiar evaluaciones entre cursos de la misma asignatura.
    """
    nombre = models.CharField(max_length=200, help_text="Nombre de la asignatura")
    codigo = models.CharField(max_length=20, unique=True, help_text="Código único de la asignatura")
    descripcion = models.TextField(blank=True, null=True, help_text="Descripción de la asignatura")
    area_conocimiento = models.CharField(max_length=100, blank=True, null=True, help_text="Área de conocimiento de la asignatura")
    activa = models.BooleanField(default=True, help_text="Indica si la asignatura está activa")
    fecha_creacion = models.DateTimeField(auto_now_add=True)
    fecha_modificacion = models.DateTimeField(auto_now=True)
    creado_por = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='asignaturas_creadas', blank=True, null=True)
    
    class Meta:
        ordering = ['nombre']
        verbose_name = 'Asignatura'
        verbose_name_plural = 'Asignaturas'
    
    def __str__(self):
        return f"{self.codigo} - {self.nombre}"
    
    def get_cursos_count(self):
        """Retorna el número de cursos asociados a esta asignatura"""
        return self.cursos.count()
    
    def get_evaluaciones_count(self):
        """Retorna el número total de evaluaciones en todos los cursos de esta asignatura"""
        return Evaluacion.objects.filter(curso__asignatura=self).count()
    
    def get_cursos_activos(self):
        """Retorna solo los cursos activos de esta asignatura"""
        return self.cursos.filter(activo=True)
    
    def copiar_evaluacion(self, evaluacion_origen, curso_destino, usuario_copia):
        """
        Copia una evaluación de un curso a otro dentro de la misma asignatura
        """
        from django.db import transaction
        
        if evaluacion_origen.curso.asignatura != self:
            raise ValueError("La evaluación debe pertenecer a un curso de esta asignatura")
        
        if curso_destino.asignatura != self:
            raise ValueError("El curso destino debe pertenecer a esta asignatura")
        
        if evaluacion_origen.curso == curso_destino:
            raise ValueError("No se puede copiar una evaluación al mismo curso")
        
        with transaction.atomic():
            # Crear nueva evaluación
            nueva_evaluacion = Evaluacion.objects.create(
                curso=curso_destino,
                tipo=evaluacion_origen.tipo,
                nombre=f"{evaluacion_origen.nombre}",
                fecha_inicio=evaluacion_origen.fecha_inicio,
                fecha_fin=evaluacion_origen.fecha_fin,
                nota_maxima=evaluacion_origen.nota_maxima,
                ponderacion=evaluacion_origen.ponderacion,
                descripcion=evaluacion_origen.descripcion,
                activa=evaluacion_origen.activa,
                creado_por=usuario_copia
            )
            
            # Copiar rúbrica si existe
            if hasattr(evaluacion_origen, 'rubrica'):
                rubrica_origen = evaluacion_origen.rubrica
                nueva_rubrica = Rubrica.objects.create(
                    evaluacion=nueva_evaluacion,
                    nombre=rubrica_origen.nombre,
                    activa=rubrica_origen.activa,
                    creado_por=usuario_copia
                )
                
                # Copiar objetivos de aprendizaje
                objetivos_mapping = {}  # Para mapear objetivos originales a nuevos
                for objetivo_origen in rubrica_origen.objetivos_aprendizaje.all():
                    nuevo_objetivo = ObjetivoAprendizaje.objects.create(
                        rubrica=nueva_rubrica,
                        nombre=objetivo_origen.nombre,
                        descripcion=objetivo_origen.descripcion,
                        orden=objetivo_origen.orden,
                        activo=objetivo_origen.activo
                    )
                    objetivos_mapping[objetivo_origen.id] = nuevo_objetivo
                
                # Copiar criterios y esperables
                for criterio_origen in rubrica_origen.criterios.all():
                    nuevo_criterio = CriterioRubrica.objects.create(
                        rubrica=nueva_rubrica,
                        nombre=criterio_origen.nombre,
                        objetivo=criterio_origen.objetivo,
                        puntaje=criterio_origen.puntaje,
                        orden=criterio_origen.orden,
                        objetivo_aprendizaje=objetivos_mapping.get(criterio_origen.objetivo_aprendizaje.id) if criterio_origen.objetivo_aprendizaje else None
                    )
                    
                    # Copiar esperables
                    for esperable_origen in criterio_origen.esperables.all():
                        Esperable.objects.create(
                            criterio=nuevo_criterio,
                            nivel=esperable_origen.nivel,
                            descripcion=esperable_origen.descripcion,
                            puntaje=esperable_origen.puntaje,
                            orden=esperable_origen.orden
                        )
            
            # Copiar recursos si existen
            for recurso_origen in evaluacion_origen.recursos.all():
                Recurso.objects.create(
                    evaluacion=nueva_evaluacion,
                    nombre=recurso_origen.nombre,
                    descripcion=recurso_origen.descripcion,
                    tipo=recurso_origen.tipo,
                    archivo_adjunto=recurso_origen.archivo_adjunto,
                    enlace_externo=recurso_origen.enlace_externo,
                    activo=recurso_origen.activo,
                    creado_por=usuario_copia
                )
            
            return nueva_evaluacion