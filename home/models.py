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

    def __str__(self):
        return self.nombre

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