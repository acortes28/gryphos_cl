from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, PasswordChangeForm, UsernameField, PasswordResetForm, SetPasswordForm
import re
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model
from django.db import models
from .models import Post, Comment
from .models import BlogPost, Curso
from .models import Evaluacion, Calificacion, Entrega
from django.contrib.auth import get_user_model
from .models import TicketSoporte, ClasificacionTicket, ComentarioTicket

User = get_user_model()

# Opciones para el campo desplegable de cursos
def get_cursos_capacitacion():
    """Función para obtener los cursos de capacitación de forma dinámica"""
    try:
        return [(curso.id, curso.nombre) for curso in Curso.objects.all()]
    except:
        # Si hay problemas con la base de datos, retornar lista vacía
        return []

CURSOS_CAPACITACION = get_cursos_capacitacion()

def validate_phone_number(value):
    # Limpiar el número de espacios y caracteres especiales
    cleaned_value = re.sub(r'[\s\-\(\)]', '', value)
    
    # Patrones válidos para números chilenos
    patterns = [
        r'^9\d{8}$',      # 912345678
    ]
    
    for pattern in patterns:
        if re.match(pattern, cleaned_value):
            return
    
    raise ValidationError('Número de teléfono inválido. Debe ser un número válido (ej: 912345678)')


def validate_gryphos_email(value):
    """
    Valida que el email tenga dominio gryphos.cl
    """
    if not value:
        raise ValidationError('El correo electrónico es obligatorio')
    
    # Convertir a minúsculas para la comparación
    email_lower = value.lower().strip()
    
    # Verificar que termine con @gryphos.cl
    if not email_lower.endswith('@gryphos.cl'):
        raise ValidationError('Solo se permiten correos electrónicos con dominio @gryphos.cl')
    
    # Verificar que tenga un formato válido de email
    if '@' not in email_lower or email_lower.count('@') != 1:
        raise ValidationError('Formato de correo electrónico inválido')
    
    # Verificar que la parte antes del @ no esté vacía
    local_part = email_lower.split('@')[0]
    if not local_part:
        raise ValidationError('El correo electrónico debe tener un nombre de usuario válido')
    
    return value
    

class RegistrationForm(UserCreationForm):
    phone_number = forms.CharField(
        max_length=15,
        widget=forms.TextInput(attrs={
            'class': 'form-control'
        }),
        validators=[validate_phone_number],
        label="Número de Teléfono")
    
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': ''
        }),
        validators=[validate_gryphos_email],
        label="Correo Electrónico",
        help_text="⚠️ Solo se permiten correos con dominio @gryphos.cl"
    )
    
    class Meta:
        model = User
        fields = ('username', 'email', 'phone_number')
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if email and User.objects.filter(email=email).exists():
            raise forms.ValidationError('Ya existe una cuenta registrada con este correo electrónico.')
        return email
    
    def __init__(self, *args, **kwargs):
        super(RegistrationForm, self).__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            if isinstance(field.widget, forms.widgets.Input):
                field.widget.attrs.update({'class': 'form-control'})


class LoginForm(AuthenticationForm):
  username = UsernameField(widget=forms.TextInput(attrs={"class": "form-control"}))
  password = forms.CharField(
      label=_("Password"),
      strip=False,
      widget=forms.PasswordInput(attrs={"autocomplete": "current-password", "class": "form-control"}),)
  

class UserPasswordResetForm(PasswordResetForm):
    email = forms.EmailField(widget=forms.EmailInput(attrs={
        'class': 'form-control'
    }))
    

class UserSetPasswordForm(SetPasswordForm):
    new_password1 = forms.CharField(max_length=50, widget=forms.PasswordInput(attrs={
        'class': 'form-control'
    }), label="Nueva contraseña")
    new_password2 = forms.CharField(max_length=50, widget=forms.PasswordInput(attrs={
        'class': 'form-control'
    }), label="Confirmar nueva contraseña")

    
class UserPasswordChangeForm(PasswordChangeForm):
    old_password = forms.CharField(max_length=50, widget=forms.PasswordInput(attrs={
        'class': 'form-control'
    }), label='Contraseña actual')
    new_password1 = forms.CharField(max_length=50, widget=forms.PasswordInput(attrs={
        'class': 'form-control'
    }), label="Nueva contraseña")
    new_password2 = forms.CharField(max_length=50, widget=forms.PasswordInput(attrs={
        'class': 'form-control'
    }), label="Confirmar nueva contraseña")


class CursoCapacitacionForm(forms.Form):
    nombre_interesado = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': ''
        }),
        label="Nombre del interesado"
    )
    
    nombre_empresa = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': ''
        }),
        label="Nombre de la empresa"
    )
    
    telefono_contacto = forms.CharField(
        max_length=15,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': ''
        }),
        label="Teléfono de contacto (opcional)",
        required=False
    )
    
    correo_contacto = forms.EmailField(
        max_length=254,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': ''
        }),
        label="Correo de contacto",
        required=True
    )
    
    curso_interes = forms.ChoiceField(
        choices=CURSOS_CAPACITACION,
        widget=forms.Select(attrs={
            'class': 'form-control',
            'placeholder': ''
        }),
        label="",
        required=True
    )


class PostForm(forms.ModelForm):
    class Meta:
        model = Post
        fields = ['curso', 'title', 'content', 'category']
        widgets = {
            'curso': forms.Select(attrs={'class': 'form-control'}),
            'title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Título del post'
            }),
            'content': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 8,
                'placeholder': 'Escribe tu post aquí... Puedes usar HTML básico como <strong>negrita</strong>, <em>cursiva</em>, <u>subrayado</u>, <br> para saltos de línea, etc.'
            }),
            'category': forms.Select(attrs={
                'class': 'form-control'
            })
        }
        labels = {
            'curso': 'Curso',
            'title': 'Título',
            'content': 'Contenido (HTML permitido)',
            'category': 'Categoría'
        }


class CommentForm(forms.ModelForm):
    class Meta:
        model = Comment
        fields = ['content']
        widgets = {
            'content': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Escribe tu comentario aquí...'
            })
        }
        labels = {
            'content': 'Comentario'
        }


class BlogPostForm(forms.ModelForm):
    class Meta:
        model = BlogPost
        fields = ['title', 'content', 'category', 'featured_image', 'excerpt']
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Título del artículo'
            }),
            'content': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 12,
                'placeholder': 'Escribe tu artículo aquí... Puedes usar HTML básico como <strong>negrita</strong>, <em>cursiva</em>, <u>subrayado</u>, <br> para saltos de línea, etc.'
            }),
            'category': forms.Select(attrs={
                'class': 'form-control'
            }),
            'featured_image': forms.FileInput(attrs={
                'class': 'form-control'
            }),
            'excerpt': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Resumen del artículo (opcional)'
            })
        }
        labels = {
            'title': 'Título',
            'content': 'Contenido (HTML permitido)',
            'category': 'Categoría',
            'featured_image': 'Imagen destacada',
            'excerpt': 'Resumen'
        }

class EvaluacionForm(forms.ModelForm):
    class Meta:
        model = Evaluacion
        fields = ['tipo', 'nombre', 'fecha_inicio', 'fecha_fin', 'nota_maxima', 'ponderacion', 'descripcion']
        widgets = {
            'tipo': forms.Select(attrs={
                'class': 'form-control',
                'placeholder': 'Selecciona el tipo de evaluación'
            }),
            'nombre': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Nombre de la evaluación'
            }),
            'fecha_inicio': forms.DateInput(attrs={
                'class': 'form-control',
                'type': 'date'
            }),
            'fecha_fin': forms.DateInput(attrs={
                'class': 'form-control',
                'type': 'date'
            }),
            'nota_maxima': forms.NumberInput(attrs={
                'class': 'form-control',
                'placeholder': 'Ej: 7.0',
                'step': '0.1',
                'min': '0'
            }),
            'ponderacion': forms.NumberInput(attrs={
                'class': 'form-control',
                'placeholder': 'Ej: 30',
                'step': '0.1',
                'min': '0',
                'max': '100'
            }),
            'descripcion': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Descripción opcional de la evaluación...'
            })
        }
        labels = {
            'tipo': 'Tipo de Evaluación',
            'nombre': 'Nombre de la Evaluación',
            'fecha_inicio': 'Fecha de Inicio',
            'fecha_fin': 'Fecha de Fin',
            'nota_maxima': 'Nota Máxima',
            'ponderacion': 'Ponderación (%)',
            'descripcion': 'Descripción (Opcional)'
        }
        help_texts = {
            'tipo': 'Selecciona el tipo de evaluación',
            'nombre': 'Nombre descriptivo de la evaluación',
            'fecha_inicio': 'Fecha de inicio del período de evaluación',
            'fecha_fin': 'Fecha límite para entregar la evaluación',
            'nota_maxima': 'Nota máxima que se puede obtener',
            'ponderacion': 'Porcentaje que representa esta evaluación en el curso',
            'descripcion': 'Descripción detallada de la evaluación (opcional)'
        }
    
    def __init__(self, *args, **kwargs):
        self.curso = kwargs.pop('curso', None)
        super().__init__(*args, **kwargs)
    
    def clean_ponderacion(self):
        ponderacion = self.cleaned_data.get('ponderacion')
        curso = self.curso
        
        if not curso:
            return ponderacion
        
        if ponderacion is None:
            raise ValidationError('La ponderación es obligatoria.')
        
        # Obtener todas las evaluaciones del curso (excluyendo la actual si estamos editando)
        evaluaciones_existentes = Evaluacion.objects.filter(curso=curso)
        
        if self.instance and self.instance.pk:
            # Si estamos editando, excluir la evaluación actual
            evaluaciones_existentes = evaluaciones_existentes.exclude(id=self.instance.id)
        
        # Calcular la suma de ponderaciones existentes
        suma_ponderaciones_existentes = evaluaciones_existentes.aggregate(
            total=models.Sum('ponderacion')
        )['total'] or 0
        
        # Calcular la ponderación total si se agrega esta nueva
        ponderacion_total = suma_ponderaciones_existentes + ponderacion
        
        if ponderacion_total > 100:
            ponderacion_disponible = 100 - suma_ponderaciones_existentes
            raise ValidationError(
                f'La ponderación total no puede exceder el 100%. '
                f'Con las evaluaciones existentes ({suma_ponderaciones_existentes}%), '
                f'solo puedes asignar hasta {ponderacion_disponible}% de ponderación.'
            )
        
        return ponderacion
    
    def clean_nombre(self):
        nombre = self.cleaned_data.get('nombre')
        curso = self.curso
        
        if not curso or not nombre:
            return nombre
        
        # Verificar si ya existe una evaluación con el mismo nombre en el curso
        evaluaciones_existentes = Evaluacion.objects.filter(curso=curso, nombre=nombre)
        
        if self.instance and self.instance.pk:
            # Si estamos editando, excluir la evaluación actual
            evaluaciones_existentes = evaluaciones_existentes.exclude(id=self.instance.id)
        
        if evaluaciones_existentes.exists():
            raise ValidationError(f'Ya existe una evaluación con el nombre "{nombre}" en este curso.')
        
        return nombre
    
    def clean(self):
        """Validación personalizada del formulario"""
        cleaned_data = super().clean()
        fecha_inicio = cleaned_data.get('fecha_inicio')
        fecha_fin = cleaned_data.get('fecha_fin')
        
        if fecha_inicio and fecha_fin and fecha_inicio > fecha_fin:
            raise ValidationError('La fecha de fin debe ser posterior a la fecha de inicio.')
        
        return cleaned_data

class EntregaForm(forms.ModelForm):
    class Meta:
        model = Entrega
        fields = ['archivo', 'comentario']
        widgets = {
            'archivo': forms.FileInput(attrs={
                'class': 'form-control',
                'accept': '.pdf,.doc,.docx,.txt,.zip,.rar,.jpg,.jpeg,.png,.xlsx,.xls,.ppt,.pptx,.csv'
            }),
            'comentario': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Comentario opcional sobre tu entrega...'
            })
        }
        labels = {
            'comentario': 'Comentario (Opcional)'
        }
        help_texts = {
            'comentario': 'Puedes agregar un comentario explicativo sobre tu entrega'
        }
    
    def __init__(self, *args, **kwargs):
        self.evaluacion = kwargs.pop('evaluacion', None)
        self.estudiante = kwargs.pop('estudiante', None)
        super().__init__(*args, **kwargs)
    
    def clean_archivo(self):
        archivo = self.cleaned_data.get('archivo')
        
        if not archivo:
            raise ValidationError('Debes seleccionar un archivo para entregar.')
        
        # Verificar tamaño del archivo (máximo 50MB)
        if archivo.size > 50 * 1024 * 1024:  # 50MB
            raise ValidationError('El archivo no puede ser mayor a 50MB.')
        
        # Verificar extensión del archivo
        extensiones_permitidas = ['.pdf', '.doc', '.docx', '.txt', '.zip', '.rar', '.jpg', '.jpeg', '.png', '.xlsx', '.xls', '.ppt', '.pptx', '.csv']
        nombre_archivo = archivo.name.lower()
        
        if not any(nombre_archivo.endswith(ext) for ext in extensiones_permitidas):
            raise ValidationError('Solo se permiten archivos PDF, Word, Excel, PowerPoint, texto, comprimidos e imágenes.')
        
        return archivo
    
    def clean(self):
        """Validación personalizada del formulario"""
        cleaned_data = super().clean()
        
        if not self.evaluacion:
            raise ValidationError('No se ha especificado la evaluación.')
        
        if not self.estudiante:
            raise ValidationError('No se ha especificado el estudiante.')
        
        # Verificar que el estudiante pueda entregar
        if not self.evaluacion.activa:
            raise ValidationError('Esta evaluación no está activa.')
        
        # Verificar fechas
        from django.utils import timezone
        ahora = timezone.now()
        
        if self.evaluacion.fecha_inicio and ahora.date() < self.evaluacion.fecha_inicio:
            raise ValidationError('La evaluación aún no ha comenzado.')
        
        if self.evaluacion.fecha_fin and ahora.date() > self.evaluacion.fecha_fin:
            raise ValidationError('La fecha límite para entregar ya ha pasado.')
        
        return cleaned_data

class CalificacionForm(forms.ModelForm):
    class Meta:
        model = Calificacion
        fields = ['estudiante', 'nota', 'retroalimentacion']
        widgets = {
            'estudiante': forms.Select(attrs={
                'class': 'form-control',
                'placeholder': 'Selecciona un estudiante'
            }),
            'nota': forms.NumberInput(attrs={
                'class': 'form-control',
                'placeholder': 'Ej: 6.5',
                'step': '0.1',
                'min': '0'
            }),
            'retroalimentacion': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Recuerda que nuestro sello de calidad es la retroalimentación al estudiante para su aprendizaje personalizado.'
            })
        }
        labels = {
            'estudiante': 'Estudiante',
            'nota': 'Nota',
            'retroalimentacion': 'Retroalimentación'
        }
        help_texts = {
            'estudiante': 'Selecciona el estudiante a calificar',
            'nota': 'Nota obtenida por el estudiante',
            'retroalimentacion': 'Comentarios y sugerencias para el estudiante'
        }
    
    def __init__(self, *args, **kwargs):
        curso = kwargs.pop('curso', None)
        evaluacion = kwargs.pop('evaluacion', None)
        estudiantes_con_entregas = kwargs.pop('estudiantes_con_entregas', None)
        super().__init__(*args, **kwargs)
        
        # Guardar la evaluación para validaciones posteriores
        if evaluacion:
            self.evaluacion = evaluacion
        
        if curso:
            if estudiantes_con_entregas is not None:
                # Usar la lista de estudiantes con entregas proporcionada
                # Pero excluir los que ya están calificados
                if evaluacion:
                    estudiantes_calificados_ids = evaluacion.calificaciones.values_list('estudiante_id', flat=True)
                    estudiantes_disponibles = estudiantes_con_entregas.exclude(id__in=estudiantes_calificados_ids)
                else:
                    estudiantes_disponibles = estudiantes_con_entregas
            else:
                # Obtener estudiantes inscritos en el curso (no staff/admin)
                estudiantes_inscritos = User.objects.filter(
                    cursos=curso,
                    is_staff=False,
                    is_superuser=False
                )
                
                # Si hay una evaluación específica, solo incluir estudiantes con entregas
                if evaluacion:
                    # Obtener estudiantes que tienen entregas para esta evaluación
                    estudiantes_con_entregas = estudiantes_inscritos.filter(
                        entregas__evaluacion=evaluacion
                    ).distinct()
                    
                    # Excluir estudiantes ya calificados
                    estudiantes_calificados_ids = evaluacion.calificaciones.values_list('estudiante_id', flat=True)
                    estudiantes_disponibles = estudiantes_con_entregas.exclude(id__in=estudiantes_calificados_ids)
                else:
                    estudiantes_disponibles = estudiantes_inscritos
            
            self.fields['estudiante'].queryset = estudiantes_disponibles.order_by('first_name', 'last_name', 'username')
    
    def clean_estudiante(self):
        """Validar que el estudiante tenga una entrega para esta evaluación"""
        estudiante = self.cleaned_data.get('estudiante')
        evaluacion = getattr(self, 'evaluacion', None)
        
        if estudiante and evaluacion:
            # Verificar que el estudiante tenga una entrega para esta evaluación
            tiene_entrega = estudiante.entregas.filter(evaluacion=evaluacion).exists()
            if not tiene_entrega:
                raise ValidationError(f'El estudiante {estudiante.get_full_name()} no tiene entregas para la evaluación "{evaluacion.nombre}". Solo se pueden calificar estudiantes que hayan entregado su trabajo.')
        
        return estudiante

class TicketSoporteForm(forms.ModelForm):
    """
    Formulario para crear tickets de soporte
    """
    # Definir campos de clasificación como ChoiceField para control total
    clasificacion = forms.ChoiceField(
        choices=[],
        widget=forms.Select(attrs={
            'class': 'form-control',
            'id': 'clasificacion-select'
        }),
        label='Clasificación',
        help_text='Selecciona la categoría principal de tu consulta'
    )
    
    subclasificacion = forms.ChoiceField(
        choices=[],
        widget=forms.Select(attrs={
            'class': 'form-control',
            'id': 'subclasificacion-select'
        }),
        label='Subclasificación',
        help_text='Selecciona la subcategoría específica'
    )
    
    class Meta:
        model = TicketSoporte
        fields = ['titulo', 'clasificacion', 'subclasificacion', 'descripcion']
        widgets = {
            'titulo': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Título del ticket de soporte'
            }),
            'descripcion': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 6,
                'placeholder': 'Describe detalladamente tu problema o consulta...'
            })
        }
        labels = {
            'titulo': 'Título',
            'descripcion': 'Descripción'
        }
        help_texts = {
            'titulo': 'Título breve que describa tu problema',
            'descripcion': 'Describe detalladamente tu problema o consulta'
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        print("=== DEBUG TICKETSOPORTEFORM __INIT__ ===")
        
        # Obtener clasificaciones activas
        from .models import ClasificacionTicket
        clasificaciones = ClasificacionTicket.objects.filter(activa=True)
        print(f"Clasificaciones encontradas en __init__: {clasificaciones.count()}")
        for c in clasificaciones:
            print(f"  - {c.nombre} (ID: {c.id})")
        
        # Configurar opciones de clasificación
        self.fields['clasificacion'].choices = [('', 'Selecciona una clasificación')] + [
            (c.nombre, c.nombre) for c in clasificaciones
        ]
        
        print(f"Opciones finales de clasificación: {len(self.fields['clasificacion'].choices)}")
        for choice in self.fields['clasificacion'].choices:
            print(f"  - {choice[1]} (valor: {choice[0]})")
        
        # Inicialmente no hay subclasificaciones
        self.fields['subclasificacion'].choices = [('', 'Primero selecciona una clasificación')]
        
        print(f"Opciones finales de subclasificación: {len(self.fields['subclasificacion'].choices)}")
        for choice in self.fields['subclasificacion'].choices:
            print(f"  - {choice[1]} (valor: {choice[0]})")
        
        print("=== FIN DEBUG TICKETSOPORTEFORM __INIT__ ===")
    
    def clean_titulo(self):
        titulo = self.cleaned_data.get('titulo')
        if len(titulo) < 10:
            raise forms.ValidationError('El título debe tener al menos 10 caracteres.')
        return titulo
    
    def clean_descripcion(self):
        descripcion = self.cleaned_data.get('descripcion')
        if len(descripcion) < 20:
            raise forms.ValidationError('La descripción debe tener al menos 20 caracteres.')
        return descripcion


class ComentarioTicketForm(forms.ModelForm):
    """
    Formulario para comentarios en tickets
    """
    class Meta:
        model = ComentarioTicket
        fields = ['contenido', 'es_interno']
        widgets = {
            'contenido': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Escribe tu comentario aquí...'
            }),
            'es_interno': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            })
        }
        labels = {
            'contenido': 'Comentario',
            'es_interno': 'Comentario interno (solo visible para staff)'
        }
        help_texts = {
            'contenido': 'Escribe tu comentario o respuesta',
            'es_interno': 'Marcar si este comentario es solo para el equipo de soporte'
        }
    
    def clean_contenido(self):
        contenido = self.cleaned_data.get('contenido')
        if len(contenido.strip()) < 5:
            raise forms.ValidationError('El comentario debe tener al menos 5 caracteres.')
        return contenido


class TicketSoporteAdminForm(forms.ModelForm):
    """
    Formulario para administradores para gestionar tickets
    """
    class Meta:
        model = TicketSoporte
        fields = ['estado', 'prioridad', 'asignado_a']
        widgets = {
            'estado': forms.Select(attrs={
                'class': 'form-control'
            }),
            'prioridad': forms.Select(attrs={
                'class': 'form-control'
            }),
            'asignado_a': forms.Select(attrs={
                'class': 'form-control'
            })
        }
        labels = {
            'estado': 'Estado del Ticket',
            'prioridad': 'Prioridad',
            'asignado_a': 'Asignar a'
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Filtrar solo usuarios admin/staff para asignación
        staff_users = User.objects.filter(is_staff=True).order_by('first_name', 'last_name')
        self.fields['asignado_a'].queryset = staff_users
        self.fields['asignado_a'].choices = [('', 'Sin asignar')] + [
            (user.id, user.get_full_name() or user.username) for user in staff_users
        ]