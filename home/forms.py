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
from .models import TicketSoporte, ClasificacionTicket, ComentarioTicket, Recurso

User = get_user_model()

# Opciones para el campo desplegable de cursos
def get_cursos_capacitacion():
    """Función para obtener los cursos de capacitación de forma dinámica"""
    try:
        return [(curso.id, curso.nombre) for curso in Curso.objects.filter(activo=True)]
    except:
        # Si hay problemas con la base de datos, retornar lista vacía
        return []

# Ya no definimos CURSOS_CAPACITACION aquí, se hará dinámicamente en el formulario

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
    username = UsernameField(
        widget=forms.TextInput(attrs={
            "class": "form-control",
            "placeholder": "",
            "autocomplete": "off"
        }),
        label="Usuario o Correo Electrónico"
    )
    password = forms.CharField(
        label=_("Password"),
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "off", "class": "form-control"}),)
    
    def clean_username(self):
        username = self.cleaned_data.get('username')
        if username:
            # Verificar si es un email
            if '@' in username:
                # Buscar usuario por email
                try:
                    user = User.objects.get(email=username)
                    return user.username
                except User.DoesNotExist:
                    raise forms.ValidationError('No existe una cuenta con este correo electrónico.')
            else:
                # Es un username, verificar que existe
                if not User.objects.filter(username=username).exists():
                    raise forms.ValidationError('No existe una cuenta con este nombre de usuario.')
        return username
  

class UserPasswordResetForm(PasswordResetForm):
    email = forms.CharField(
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': ''
        }),
        label="Usuario o Correo Electrónico"
    )
    
    def clean_email(self):
        email_or_username = self.cleaned_data.get('email')
        if email_or_username:
            # Verificar si es un email
            if '@' in email_or_username:
                # Buscar usuario por email
                try:
                    user = User.objects.get(email=email_or_username)
                    return user.email
                except User.DoesNotExist:
                    raise forms.ValidationError('No existe una cuenta con este correo electrónico.')
            else:
                # Es un username, buscar por username
                try:
                    user = User.objects.get(username=email_or_username)
                    return user.email
                except User.DoesNotExist:
                    raise forms.ValidationError('No existe una cuenta con este nombre de usuario.')
        return email_or_username
    

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
        choices=[],
        widget=forms.Select(attrs={
            'class': 'form-control',
            'placeholder': ''
        }),
        label="",
        required=True
    )
    
    def __init__(self, *args, **kwargs):
        super(CursoCapacitacionForm, self).__init__(*args, **kwargs)
        # Obtener las opciones de cursos dinámicamente
        self.fields['curso_interes'].choices = get_cursos_capacitacion()


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
            }, format='%Y-%m-%d'),
            'fecha_fin': forms.DateInput(attrs={
                'class': 'form-control',
                'type': 'date'
            }, format='%Y-%m-%d'),
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
        fields = ['estudiante', 'retroalimentacion', 'nota']
        widgets = {
            'estudiante': forms.Select(attrs={
                'class': 'form-control',
                'placeholder': 'Selecciona un estudiante'
            }),
            'retroalimentacion': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Recuerda que nuestro sello de calidad es la retroalimentación al estudiante para su aprendizaje personalizado.'
            }),
            'nota': forms.NumberInput(attrs={
                'class': 'form-control',
                'id': 'id_nota_calculada',
                'readonly': 'readonly',
                'step': '0.1',
                'min': '0'
            })
        }
        labels = {
            'estudiante': 'Estudiante',
            'retroalimentacion': 'Retroalimentación',
            'nota': 'Nota Calculada'
        }
        help_texts = {
            'estudiante': 'Selecciona el estudiante a calificar',
            'retroalimentacion': 'Comentarios y sugerencias para el estudiante',
            'nota': 'Nota calculada automáticamente basada en los criterios seleccionados'
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
                # Excluir los que ya están calificados para el formulario
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
                    
                    # Excluir estudiantes ya calificados para el formulario
                    estudiantes_calificados_ids = evaluacion.calificaciones.values_list('estudiante_id', flat=True)
                    estudiantes_disponibles = estudiantes_con_entregas.exclude(id__in=estudiantes_calificados_ids)
                else:
                    estudiantes_disponibles = estudiantes_inscritos
            
            self.fields['estudiante'].queryset = estudiantes_disponibles.order_by('first_name', 'last_name', 'username')
        
        # Agregar campos dinámicos para cada criterio de la rúbrica
        if evaluacion and hasattr(evaluacion, 'rubrica'):
            rubrica = evaluacion.rubrica
            if rubrica:
                # Guardar los criterios para uso posterior en el template
                self.criterios_rubrica = list(rubrica.criterios.all())
                
                for criterio in rubrica.criterios.all():
                    # Crear opciones para este criterio basadas en sus esperables
                    choices = [('', 'Selecciona un nivel...')]
                    for esperable in criterio.esperables.all():
                        # Asegurar que el puntaje se muestre con punto decimal
                        puntaje_str = str(esperable.puntaje).replace(',', '.')
                        choices.append((esperable.id, f"{puntaje_str} pts - {esperable.nivel} - {esperable.descripcion}"))
                    
                    # Crear el campo para este criterio
                    field_name = f'criterio_{criterio.id}'
                    self.fields[field_name] = forms.ChoiceField(
                        choices=choices,
                        required=True,
                        widget=forms.Select(attrs={
                            'class': 'form-control',
                            'data-criterio-id': criterio.id,
                            'data-criterio-nombre': criterio.nombre
                        }),
                        label=f"{criterio.nombre}"
                    )
                    
                    # Guardar información adicional del criterio para uso en el template
                    if not hasattr(self, 'criterios_info'):
                        self.criterios_info = {}
                    self.criterios_info[criterio.id] = {
                        'nombre': criterio.nombre,
                        'field_name': field_name
                    }
    
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
    
    def clean(self):
        """Validar que se hayan seleccionado esperables para todos los criterios"""
        cleaned_data = super().clean()
        evaluacion = getattr(self, 'evaluacion', None)
        
        if evaluacion and hasattr(evaluacion, 'rubrica'):
            rubrica = evaluacion.rubrica
            if rubrica:
                for criterio in rubrica.criterios.all():
                    field_name = f'criterio_{criterio.id}'
                    if field_name in self.fields:
                        esperable_id = cleaned_data.get(field_name)
                        if not esperable_id:
                            self.add_error(field_name, f'Debes seleccionar un nivel para el criterio "{criterio.nombre}".')
        
        return cleaned_data

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
    
    subclasificacion = forms.CharField(
        max_length=100,
        widget=forms.Select(attrs={
            'class': 'form-control',
            'id': 'subclasificacion-select'
        }),
        label='Subclasificación',
        help_text='Selecciona la subcategoría específica'
    )
    
    class Meta:
        model = TicketSoporte
        fields = ['titulo', 'descripcion']
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
        
        # Obtener clasificaciones activas
        from .models import ClasificacionTicket
        clasificaciones = ClasificacionTicket.objects.filter(activa=True)
        
        # Configurar opciones de clasificación
        self.fields['clasificacion'].choices = [('', 'Selecciona una clasificación')] + [
            (c.nombre, c.nombre) for c in clasificaciones
        ]
        
        # Configurar subclasificación como campo de texto con opciones iniciales
        self.fields['subclasificacion'].widget.choices = [('', 'Primero selecciona una clasificación')]
        # Deshabilitar la validación inicial de subclasificación
        self.fields['subclasificacion'].required = False
        
    
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
    
    def clean_subclasificacion(self):
        """
        Validación personalizada para subclasificación que permite valores dinámicos
        """
        subclasificacion = self.cleaned_data.get('subclasificacion')
        clasificacion = self.cleaned_data.get('clasificacion')
        
        if not subclasificacion:
            raise forms.ValidationError('Debes seleccionar una subclasificación.')
        
        if not clasificacion:
            raise forms.ValidationError('Debes seleccionar una clasificación primero.')
        
        # Verificar que la subclasificación existe para la clasificación seleccionada
        try:
            from .models import ClasificacionTicket, SubclasificacionTicket
            clasificacion_obj = ClasificacionTicket.objects.get(nombre=clasificacion, activa=True)
            subclasificacion_obj = SubclasificacionTicket.objects.get(
                clasificacion=clasificacion_obj,
                nombre=subclasificacion,
                activa=True
            )
            return subclasificacion
        except (ClasificacionTicket.DoesNotExist, SubclasificacionTicket.DoesNotExist):
            raise forms.ValidationError('La subclasificación seleccionada no es válida para la clasificación elegida.')
    
    def clean_clasificacion(self):
        """
        Validación personalizada para clasificación
        """
        clasificacion = self.cleaned_data.get('clasificacion')
        
        if not clasificacion:
            raise forms.ValidationError('Debes seleccionar una clasificación.')
        
        # Verificar que la clasificación existe y está activa
        try:
            from .models import ClasificacionTicket
            ClasificacionTicket.objects.get(nombre=clasificacion, activa=True)
            return clasificacion
        except ClasificacionTicket.DoesNotExist:
            raise forms.ValidationError('La clasificación seleccionada no es válida.')
    
    def save(self, commit=True):
        """
        Guardar el ticket con los campos de clasificación y subclasificación
        """
        ticket = super().save(commit=False)
        
        # Asignar los campos de clasificación y subclasificación
        ticket.clasificacion = self.cleaned_data.get('clasificacion')
        ticket.subclasificacion = self.cleaned_data.get('subclasificacion')
        
        if commit:
            ticket.save()
        
        return ticket


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


class RecursoForm(forms.ModelForm):
    """
    Formulario para crear y editar recursos de aprendizaje
    """
    class Meta:
        model = Recurso
        fields = ['nombre', 'descripcion', 'tipo', 'archivo_adjunto', 'enlace_externo']
        widgets = {
            'nombre': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Nombre del recurso'
            }),
            'descripcion': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Descripción detallada del recurso...'
            }),
            'tipo': forms.Select(attrs={
                'class': 'form-control',
                'placeholder': 'Selecciona el tipo de recurso'
            }),
            'archivo_adjunto': forms.FileInput(attrs={
                'class': 'form-control',
                'accept': '.pdf,.doc,.docx,.txt,.zip,.rar,.jpg,.jpeg,.png,.mp4,.mp3,.ppt,.pptx,.xlsx,.xls'
            }),
            'enlace_externo': forms.URLInput(attrs={
                'class': 'form-control',
                'placeholder': 'https://ejemplo.com/recurso'
            })
        }
        labels = {
            'nombre': 'Nombre del Recurso',
            'descripcion': 'Descripción',
            'tipo': 'Tipo de Recurso',
            'archivo_adjunto': 'Archivo Adjunto',
            'enlace_externo': 'Enlace Externo'
        }
        help_texts = {
            'nombre': 'Nombre descriptivo del recurso',
            'descripcion': 'Descripción detallada del contenido del recurso',
            'tipo': 'Categoría del recurso',
            'archivo_adjunto': 'Archivo del recurso (opcional si tienes enlace externo)',
            'enlace_externo': 'URL del recurso (opcional si tienes archivo adjunto)'
        }
    
    def __init__(self, *args, **kwargs):
        self.evaluacion = kwargs.pop('evaluacion', None)
        super().__init__(*args, **kwargs)
    
    def clean(self):
        """
        Validación personalizada del formulario
        """
        cleaned_data = super().clean()
        archivo_adjunto = cleaned_data.get('archivo_adjunto')
        enlace_externo = cleaned_data.get('enlace_externo')
        
        # Verificar que se proporcione al menos un archivo o enlace
        if not archivo_adjunto and not enlace_externo:
            raise forms.ValidationError(
                'Debes proporcionar al menos un archivo adjunto o un enlace externo.'
            )
        
        # Validar tamaño del archivo si se proporciona
        if archivo_adjunto:
            if archivo_adjunto.size > 50 * 1024 * 1024:  # 50MB
                raise forms.ValidationError(
                    'El archivo no puede ser mayor a 50MB.'
                )
            
            # Validar extensión del archivo
            extensiones_permitidas = [
                '.pdf', '.doc', '.docx', '.txt', '.zip', '.rar', 
                '.jpg', '.jpeg', '.png', '.mp4', '.mp3', '.ppt', '.pptx', '.xlsx', '.xls'
            ]
            nombre_archivo = archivo_adjunto.name.lower()
            
            if not any(nombre_archivo.endswith(ext) for ext in extensiones_permitidas):
                raise forms.ValidationError(
                    'Solo se permiten archivos PDF, Word, Excel, PowerPoint, texto, '
                    'comprimidos, imágenes, videos y audio.'
                )
        
        return cleaned_data
    
    def save(self, commit=True):
        """
        Guardar el recurso con la evaluación asociada
        """
        recurso = super().save(commit=False)
        
        if self.evaluacion:
            recurso.evaluacion = self.evaluacion
        
        if commit:
            recurso.save()
        
        return recurso