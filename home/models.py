import uuid
from django.db import models
from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.contrib.postgres.fields import JSONField

class CustomUser(AbstractUser):
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    company_name = models.CharField(max_length=100, blank=True, null=True)
    company_rut = models.CharField(max_length=12, blank=True, null=True)  # Consider adding specific validation
    company_address = models.CharField(max_length=255, blank=True, null=True)
    admin_name = models.CharField(max_length=100, blank=True, null=True)

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
    descripcion = models.TextField(blank=True, null=True)
    fecha_inicio = models.DateField(blank=True, null=True)
    fecha_fin = models.DateField(blank=True, null=True)
    activo = models.BooleanField(default=True)
    
    # Nuevos campos para la página de detalle
    docente_nombre = models.CharField(max_length=100, blank=True, null=True)
    docente_titulos = models.TextField(blank=True, null=True, help_text="Títulos y certificaciones del docente")
    docente_trayectoria = models.TextField(blank=True, null=True, help_text="Experiencia y trayectoria profesional del docente")
    docente_foto = models.ImageField(upload_to='docentes/', blank=True, null=True)
    
    requisitos = models.TextField(blank=True, null=True, help_text="Requisitos previos para el curso")
    material_introductorio = models.TextField(blank=True, null=True, help_text="Material introductorio del curso")
    material_curso = models.TextField(blank=True, null=True, help_text="Material principal del curso")
    
    # Información adicional del curso
    duracion = models.CharField(max_length=50, blank=True, null=True, help_text="Duración del curso (ej: 8 semanas)")
    modalidad = models.CharField(max_length=50, blank=True, null=True, help_text="Modalidad del curso (ej: Online, Presencial, Híbrido)")
    nivel = models.CharField(max_length=50, blank=True, null=True, help_text="Nivel del curso (ej: Básico, Intermedio, Avanzado)")
    
    # Archivos del curso
    archivo_introductorio = models.FileField(upload_to='cursos/material_introductorio/', blank=True, null=True)
    archivo_curso = models.FileField(upload_to='cursos/material_curso/', blank=True, null=True)

    def __str__(self):
        return self.nombre
    
    def get_proximas_videollamadas(self):
        """Obtiene las próximas videollamadas programadas para este curso"""
        from django.utils import timezone
        from datetime import datetime, timedelta
        
        ahora = timezone.localtime(timezone.now())
        dia_actual = ahora.weekday()
        hora_actual = ahora.time()
        
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
            hora_actual = ahora.time()
            dia_actual = ahora.weekday()
            
            logger.debug(f"Videollamada {self.id}: activa={self.activa}, dia_semana={self.dia_semana}, dia_actual={dia_actual}, hora_inicio={self.hora_inicio}, hora_fin={self.hora_fin}, hora_actual={hora_actual}")
            
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