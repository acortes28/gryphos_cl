from django.shortcuts import render, redirect
from .forms import LoginForm, RegistrationForm, UserPasswordResetForm, UserSetPasswordForm, UserPasswordChangeForm, CursoCapacitacionForm, CURSOS_CAPACITACION
from django.contrib.auth import logout
from django.contrib.auth import views as auth_views
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from .models import RegistrationLink
from django.http import JsonResponse, HttpResponse
from django.core.mail import send_mail
from django.contrib import messages
from django.conf import settings

User = get_user_model()  # Obtener el modelo de usuario personalizado

def generate_registration_link(request):
    if request.user.is_superuser:
        new_link = RegistrationLink.objects.create(creator=request.user)
        return JsonResponse({'link': str(new_link.uuid)})
    else:
        return JsonResponse({'error': 'Unauthorized'}, status=403)

def registration(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            print('Account created successfully!')
            return redirect('/accounts/login/')
        else:
            print("Registration failed!")
            print("Form errors:", form.errors)
            for field_name, errors in form.errors.items():
                print(f"Field {field_name}: {errors}")
    else:
        form = RegistrationForm()
    context = {'form': form}
    return render(request, 'accounts/sign-up.html', context)

class UserLoginView(auth_views.LoginView):
    template_name = 'accounts/sign-in.html'
    form_class = LoginForm
    success_url = '/'

class UserPasswordResetView(auth_views.PasswordResetView):
    template_name = 'accounts/password_reset.html'
    form_class = UserPasswordResetForm


class UserPasswordResetConfirmView(auth_views.PasswordResetConfirmView):
    template_name = 'accounts/password_reset_confirm.html'
    form_class = UserSetPasswordForm


class UserPasswordChangeView(auth_views.PasswordChangeView):
    template_name = 'accounts/password_change.html'
    form_class = UserPasswordChangeForm

def user_logout_view(request):
    logout(request)
    return redirect('/accounts/login/')

def index(request):
    return render(request, 'pages/index.html')

def que_hacemos(request):
    return render(request, 'pages/que-hacemos.html')

def quienes_somos(request):
    if request.method == 'POST':
        # Obtener datos del formulario
        nombre = request.POST.get('nombre', '')
        email = request.POST.get('email', '')
        mensaje = request.POST.get('message', '')
        
        if nombre and email and mensaje:
            try:
                # Enviar correo
                subject = f'Nuevo mensaje de contacto de {nombre}'
                message = f"""
                Nuevo mensaje de contacto recibido:
                
                Nombre: {nombre}
                Email: {email}
                Mensaje: {mensaje}
                
                Este mensaje fue enviado desde el formulario de contacto de la página "Quiénes somos".
                """
                print("Sending email to: contacto@gryphos.cl")
                # Enviar a la dirección de contacto de Gryphos
                send_mail(
                    subject=subject,
                    message=message,
                    from_email=settings.DEFAULT_FROM_EMAIL if hasattr(settings, 'DEFAULT_FROM_EMAIL') else 'contacto@gryphos.cl',
                    recipient_list=['contacto@gryphos.cl'],
                    fail_silently=False,
                )
                print("Email sent successfully!")
                
                messages.success(request, '¡Mensaje enviado exitosamente! Nos pondremos en contacto contigo pronto.')
                
            except Exception as e:
                messages.error(request, 'Error al enviar el mensaje. Por favor, intenta nuevamente.')
                print(f"Error enviando email: {e}")
        else:
            messages.error(request, 'Por favor, completa todos los campos del formulario.')
    
    return render(request, 'pages/quienes-somos.html')

@login_required
def portal_cliente(request):
    return render(request, 'pages/portal-cliente.html')


def enviar_correo_inscripcion(nombre_interesado, nombre_empresa, telefono_contacto, curso_interes):
    """
    Función para enviar correo de inscripción al curso de capacitación
    """
    # Obtener el nombre legible del curso
    curso_nombre = dict(CURSOS_CAPACITACION).get(curso_interes, curso_interes)
    
    subject = f'Nueva inscripción para curso de capacitación - {nombre_interesado}'
    message = f"""
    Se ha recibido una nueva inscripción para el curso de capacitación:
    
    Nombre del interesado: {nombre_interesado}
    Nombre de la empresa: {nombre_empresa}
    Teléfono de contacto: {telefono_contacto}
    Curso de interés: {curso_nombre}
    
    Este mensaje fue enviado desde el formulario de inscripción de cursos de capacitación.
    """
    
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL if hasattr(settings, 'DEFAULT_FROM_EMAIL') else 'contacto@gryphos.cl',
            recipient_list=['contacto@gryphos.cl'],
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Error enviando correo de inscripción: {e}")
        return False


def inscripcion_curso(request):
    """
    Vista para el formulario de inscripción al curso de capacitación
    """
    if request.method == 'POST':
        form = CursoCapacitacionForm(request.POST)
        if form.is_valid():
            nombre_interesado = form.cleaned_data['nombre_interesado']
            nombre_empresa = form.cleaned_data['nombre_empresa']
            telefono_contacto = form.cleaned_data['telefono_contacto']
            curso_interes = form.cleaned_data['curso_interes']
            
            # Enviar correo
            if enviar_correo_inscripcion(nombre_interesado, nombre_empresa, telefono_contacto, curso_interes):
                messages.success(request, '¡Inscripción enviada exitosamente! Nos pondremos en contacto contigo pronto.')
                return redirect('inscripcion-curso')
            else:
                messages.error(request, 'Hubo un error al enviar la inscripción. Por favor, intenta nuevamente.')
        else:
            messages.error(request, 'Por favor, corrige los errores en el formulario.')
    else:
        form = CursoCapacitacionForm()
    
    context = {'form': form}
    return render(request, 'pages/inscripcion-curso.html', context)