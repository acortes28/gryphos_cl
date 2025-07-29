from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, PasswordChangeForm, UsernameField, PasswordResetForm, SetPasswordForm
import re
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model
from .models import Post, Comment
from .models import BlogPost, Curso
from .models import Evaluacion, Calificacion
from django.contrib.auth import get_user_model

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
        fields = ['tipo', 'nombre', 'fecha_evaluacion', 'nota_maxima', 'ponderacion', 'descripcion']
        widgets = {
            'tipo': forms.Select(attrs={
                'class': 'form-control',
                'placeholder': 'Selecciona el tipo de evaluación'
            }),
            'nombre': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Nombre de la evaluación'
            }),
            'fecha_evaluacion': forms.DateInput(attrs={
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
            'fecha_evaluacion': 'Fecha de Evaluación',
            'nota_maxima': 'Nota Máxima',
            'ponderacion': 'Ponderación (%)',
            'descripcion': 'Descripción (Opcional)'
        }
        help_texts = {
            'tipo': 'Selecciona el tipo de evaluación',
            'nombre': 'Nombre descriptivo de la evaluación',
            'fecha_evaluacion': 'Fecha en que se realizará la evaluación',
            'nota_maxima': 'Nota máxima que se puede obtener',
            'ponderacion': 'Porcentaje que representa esta evaluación en el curso',
            'descripcion': 'Descripción detallada de la evaluación (opcional)'
        }

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
                'placeholder': 'Retroalimentación para el estudiante (opcional)...'
            })
        }
        labels = {
            'estudiante': 'Estudiante',
            'nota': 'Nota',
            'retroalimentacion': 'Retroalimentación (Opcional)'
        }
        help_texts = {
            'estudiante': 'Selecciona el estudiante a calificar',
            'nota': 'Nota obtenida por el estudiante',
            'retroalimentacion': 'Comentarios y sugerencias para el estudiante'
        }
    
    def __init__(self, *args, **kwargs):
        curso = kwargs.pop('curso', None)
        super().__init__(*args, **kwargs)
        
        if curso:
            # Filtrar solo estudiantes (no staff/admin) que están inscritos en el curso
            self.fields['estudiante'].queryset = User.objects.filter(
                cursos=curso,
                is_staff=False,
                is_superuser=False
            ).order_by('first_name', 'last_name', 'username')