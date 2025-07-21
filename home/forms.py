from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, PasswordChangeForm, UsernameField, PasswordResetForm, SetPasswordForm
import re
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model
from .models import Post, Comment

User = get_user_model()

# Opciones para el campo desplegable de cursos
CURSOS_CAPACITACION = [
    ('gestion_para_pymes', 'Gestion para PYMES'),
]

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
    

class RegistrationForm(UserCreationForm):
    phone_number = forms.CharField(
        max_length=15,
        widget=forms.TextInput(attrs={
            'class': 'form-control'
        }),
        validators=[validate_phone_number],
        label="Número de Teléfono")
    class Meta:
        model = User
        fields = ('username', 'email', 'phone_number')
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
    }), label="New Password")
    new_password2 = forms.CharField(max_length=50, widget=forms.PasswordInput(attrs={
        'class': 'form-control'
    }), label="Confirm New Password")

    
class UserPasswordChangeForm(PasswordChangeForm):
    old_password = forms.CharField(max_length=50, widget=forms.PasswordInput(attrs={
        'class': 'form-control'
    }), label='Old Password')
    new_password1 = forms.CharField(max_length=50, widget=forms.PasswordInput(attrs={
        'class': 'form-control'
    }), label="New Password")
    new_password2 = forms.CharField(max_length=50, widget=forms.PasswordInput(attrs={
        'class': 'form-control'
    }), label="Confirm New Password")


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
        fields = ['title', 'content', 'category']
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Título del post'
            }),
            'content': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 5,
                'placeholder': 'Escribe tu post aquí...'
            }),
            'category': forms.Select(attrs={
                'class': 'form-control'
            })
        }
        labels = {
            'title': 'Título',
            'content': 'Contenido',
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