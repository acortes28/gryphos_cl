from django.shortcuts import render, redirect, get_object_or_404
import time
from .forms import LoginForm, RegistrationForm, UserPasswordResetForm, UserSetPasswordForm, UserPasswordChangeForm, CursoCapacitacionForm, CURSOS_CAPACITACION, PostForm, CommentForm, BlogPostForm, EvaluacionForm, CalificacionForm
from django.contrib.auth import logout
from django.contrib.auth import views as auth_views
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from .models import RegistrationLink, Post, Comment, Curso, BlogPost, InscripcionCurso, Evaluacion, Calificacion
from django.http import JsonResponse, HttpResponseRedirect
from django.core.mail import send_mail
from django.contrib import messages
from django.conf import settings
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.html import strip_tags
from django.utils.safestring import mark_safe
import requests
import logging
import traceback
from datetime import datetime, timedelta
import jwt
from django.db.models import Avg, Min, Max, Count
from decimal import Decimal

logger = logging.getLogger(__name__)

User = get_user_model()  # Obtener el modelo de usuario personalizado

def generate_registration_link(request):
    if request.user.is_superuser:
        new_link = RegistrationLink.objects.create(creator=request.user)
        return JsonResponse({'link': str(new_link.uuid)})
    else:
        return JsonResponse({'error': 'Unauthorized'}, status=403)

def enviar_correo_activacion(request, user):
    """
    Envía un correo de activación de cuenta al usuario registrado.
    """
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    activation_link = request.build_absolute_uri(
        reverse('activate-account', kwargs={'uidb64': uid, 'token': token})
    )
    subject = 'Activa tu cuenta en Gryphos Consulting'
    message = f"""
Hola {user.username},

Gracias por registrarte en Gryphos Consulting.

Por favor, haz clic en el siguiente enlace para activar tu cuenta:
{activation_link}

Si no solicitaste este registro, puedes ignorar este correo.

Saludos,
El equipo de Gryphos
"""
    send_mail(
        subject=subject,
        message=message,
        from_email=settings.DEFAULT_FROM_EMAIL if hasattr(settings, 'DEFAULT_FROM_EMAIL') else 'contacto@gryphos.cl',
        recipient_list=[user.email],
        fail_silently=False,
    )


def registration(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            # Verificar si el email ya está registrado
            email = form.cleaned_data['email']
            if User.objects.filter(email=email).exists():
                messages.error(request, 'Ya existe una cuenta registrada con este correo electrónico.')
                return render(request, 'accounts/sign-up.html', {'form': form})
            
            user = form.save(commit=False)
            user.is_active = False  # Usuario inactivo hasta confirmar correo
            user.save()
            enviar_correo_activacion(request, user)
            messages.success(request, '¡Registro exitoso! Revisa tu correo para activar tu cuenta.')
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


def activate_account(request, uidb64, token):
    """
    Vista para activar la cuenta de usuario desde el link de activación.
    """
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, '¡Cuenta activada correctamente! Ya puedes iniciar sesión.')
        return redirect('/accounts/login/')
    else:
        messages.error(request, 'El enlace de activación no es válido o ha expirado.')
        return render(request, 'accounts/activation_invalid.html')

class UserLoginView(auth_views.LoginView):
    template_name = 'accounts/sign-in.html'
    form_class = LoginForm
    success_url = '/portal-cliente/'
    
    def get(self, request, *args, **kwargs):
        # Verificar si la sesión expiró
        if request.GET.get('expired'):
            messages.warning(request, 'Tu sesión ha expirado por inactividad. Por favor, inicia sesión nuevamente.')
        return super().get(request, *args, **kwargs)
    
    def form_valid(self, form):
        """Override para agregar logging al login exitoso"""
        response = super().form_valid(form)
        
        # Log del login exitoso
        logger.info(f"Login exitoso para usuario: {form.get_user()}")
        logger.info(f"Session key después del login: {self.request.session.session_key}")
        logger.info(f"Usuario autenticado: {self.request.user.is_authenticated}")
        
        # Inicializar la última actividad en la sesión
        self.request.session['last_activity'] = time.time()
        self.request.session.save()
        
        return response

class UserPasswordResetView(auth_views.PasswordResetView):
    template_name = 'accounts/password_reset.html'
    form_class = UserPasswordResetForm
    
    def form_valid(self, form):
        email = form.cleaned_data['email']
        logger.info(f"Iniciando proceso de recuperación de contraseña para: {email}")
        
        try:
            # Verificar si el email existe en la base de datos
            if not User.objects.filter(email=email).exists():
                logger.warning(f"Intento de recuperación de contraseña para email inexistente: {email}")
                messages.error(self.request, 'No existe una cuenta registrada con este correo electrónico.')
                return self.form_invalid(form)
            
            # Si el email existe, proceder con el envío
            logger.info(f"Enviando correo de recuperación a: {email}")
            response = super().form_valid(form)
            messages.success(self.request, 'Se ha enviado un correo con las instrucciones para restablecer tu contraseña.')
            logger.info(f"Correo de recuperación enviado exitosamente a: {email}")
            return response
            
        except Exception as e:
            logger.error(f"Error al enviar correo de recuperación a {email}: {str(e)}")
            messages.error(self.request, 'Error al enviar el correo de recuperación. Por favor, intenta nuevamente.')
            return self.form_invalid(form)
    
    def form_invalid(self, form):
        logger.warning(f"Formulario de recuperación de contraseña inválido: {form.errors}")
        return super().form_invalid(form)


class UserPasswordResetConfirmView(auth_views.PasswordResetConfirmView):
    template_name = 'accounts/password_reset_confirm.html'
    form_class = UserSetPasswordForm


class UserPasswordChangeView(auth_views.PasswordChangeView):
    template_name = 'accounts/password_change.html'
    form_class = UserPasswordChangeForm

def user_logout_view(request):
    logout(request)
    return redirect('/')

def index(request):
    # Si el usuario está logueado, redirigir al portal de miembros
    if request.user.is_authenticated:
        return redirect('user_space')
    
    # Obtener todos los cursos activos para mostrar en la página principal
    cursos_activos = Curso.objects.filter(activo=True).order_by('nombre')
    context = {
        'cursos_activos': cursos_activos,
    }
    return render(request, 'pages/index.html', context)

def que_hacemos(request):
    # Si el usuario está logueado, redirigir al portal de miembros
    if request.user.is_authenticated:
        return redirect('user_space')
    return render(request, 'pages/que-hacemos.html')

def quienes_somos(request):
    # Si el usuario está logueado, redirigir al portal de miembros
    if request.user.is_authenticated:
        return redirect('user_space')
    
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
    logger.info(f"Acceso al portal del cliente - Usuario: {request.user.username}")
    logger.debug(f"Request method: {request.method}")
    logger.debug(f"Request path: {request.path}")
    logger.debug(f"Request GET params: {request.GET}")
    logger.debug(f"Request POST params: {request.POST}")
    
    try:
        logger.debug("Obteniendo cursos del usuario...")
        cursos_usuario = request.user.cursos.all()
        logger.debug(f"Usuario {request.user.username} tiene {cursos_usuario.count()} cursos")
        
        # Log detallado de los cursos
        for curso in cursos_usuario:
            logger.debug(f"Curso: {curso.nombre} (ID: {curso.id})")
            logger.debug(f"  - Videollamadas: {curso.videollamadas.count()}")
            for v in curso.videollamadas.all():
                logger.debug(f"    * Videollamada: {v} (activa: {v.activa})")
        
        context = {
            'cursos_usuario': cursos_usuario,
            'request': request
        }
        
        logger.debug(f"Contexto preparado para portal del cliente")
        logger.debug(f"Template a renderizar: pages/portal-cliente.html")
        
        # Intentar renderizar el template
        logger.debug("Iniciando renderizado del template...")
        response = render(request, 'pages/portal-cliente.html', context)
        logger.debug(f"Template renderizado exitosamente")
        logger.debug(f"Response status: {getattr(response, 'status_code', 'N/A')}")
        logger.debug(f"Response content length: {len(response.content) if hasattr(response, 'content') else 'N/A'}")
        
        logger.info(f"Portal del cliente renderizado exitosamente para {request.user.username}")
        return response
        
    except Exception as e:
        logger.error(f"Error en portal_cliente para usuario {request.user.username}: {str(e)}")
        logger.error(f"Tipo de error: {type(e).__name__}")
        logger.error(f"Traceback completo: {traceback.format_exc()}")
        raise


def debug_session(request):
    """
    Vista de debug para verificar el estado de la sesión
    """
    if not settings.DEBUG:
        return HttpResponse("Debug solo disponible en modo desarrollo", status=403)
    
    # Información básica de la sesión
    session_info = {
        'session_key': request.session.session_key,
        'session_exists': request.session.session_key is not None,
        'session_data': dict(request.session),
        'session_modified': request.session.modified,
    }
    
    # Información del usuario
    user_info = {
        'user_authenticated': request.user.is_authenticated,
        'user': str(request.user),
        'user_id': request.user.id if request.user.is_authenticated else None,
        'user_backend': getattr(request.user, '_auth_user_backend', None),
    }
    
    # Información de cookies
    cookie_info = {
        'sessionid': request.COOKIES.get('sessionid'),
        'csrftoken': request.COOKIES.get('csrftoken'),
        'all_cookies': dict(request.COOKIES),
    }
    
    # Información de headers
    headers_info = {
        'user_agent': request.META.get('HTTP_USER_AGENT'),
        'referer': request.META.get('HTTP_REFERER'),
        'host': request.META.get('HTTP_HOST'),
    }
    
    debug_info = {
        'session': session_info,
        'user': user_info,
        'cookies': cookie_info,
        'headers': headers_info,
        'timestamp': str(datetime.now()),
    }
    
    return JsonResponse(debug_info, json_dumps_params={'indent': 2})


def enviar_correo_instrucciones_pago(request, inscripcion):
    """
    Función para enviar correo con instrucciones de pago al interesado
    """
    from django.template.loader import render_to_string
    from django.utils.html import strip_tags
    
    curso_nombre = inscripcion.curso.nombre
    fecha_solicitud = inscripcion.fecha_solicitud.strftime('%d/%m/%Y %H:%M')
    
    # Formatear el precio con separación de miles usando punto (formato chileno)
    curso_precio_formateado = f"{inscripcion.curso.precio:,.0f}".replace(",", ".")
    
    # Renderizar el template HTML
    html_message = render_to_string('emails/instrucciones_pago.html', {
        'nombre_interesado': inscripcion.nombre_interesado,
        'nombre_empresa': inscripcion.nombre_empresa,
        'curso_nombre': curso_nombre,
        'fecha_solicitud': fecha_solicitud,
        'correo_contacto': inscripcion.correo_contacto,
        'curso_precio': inscripcion.curso.precio,
        'curso_precio_formateado': curso_precio_formateado,
        'dias_plazo_pago': inscripcion.curso.dias_plazo_pago,
    })
    
    # Crear versión de texto plano
    plain_message = strip_tags(html_message)
    
    subject = f'Instrucciones de Pago - Curso {curso_nombre} - Gryphos Consulting'
    
    try:
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL if hasattr(settings, 'DEFAULT_FROM_EMAIL') else 'contacto@gryphos.cl',
            recipient_list=[inscripcion.correo_contacto],
            html_message=html_message,
            fail_silently=False,
        )
        logger.info(f"Correo de instrucciones de pago enviado exitosamente a {inscripcion.correo_contacto}")
        return True

    except Exception as e:
        logger.error(f"Error enviando correo de instrucciones de pago: {e}")
        return False


def enviar_correo_bienvenida(request, user, password_temp, curso_nombre):
    """
    Función para enviar correo de bienvenida con credenciales al nuevo usuario
    """
    from django.template.loader import render_to_string
    from django.utils.html import strip_tags
    
    # Generar URLs
    login_url = request.build_absolute_uri('/accounts/login/')
    change_password_url = request.build_absolute_uri('/accounts/password_change/')
    
    # Renderizar el template HTML
    html_message = render_to_string('emails/bienvenida_usuario.html', {
        'nombre_usuario': user.get_full_name() or user.username,
        'username': user.username,
        'password_temp': password_temp,
        'email': user.email,
        'curso_nombre': curso_nombre,
        'login_url': login_url,
        'change_password_url': change_password_url,
    })
    
    # Crear versión de texto plano
    plain_message = strip_tags(html_message)
    
    subject = f'¡Bienvenido a Gryphos Consulting! - Acceso a {curso_nombre}'
    
    try:
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL if hasattr(settings, 'DEFAULT_FROM_EMAIL') else 'contacto@gryphos.cl',
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )
        logger.info(f"Correo de bienvenida enviado exitosamente a {user.email}")
        return True
    except Exception as e:
        logger.error(f"Error enviando correo de bienvenida: {e}")
        return False


def enviar_correo_inscripcion(nombre_interesado, nombre_empresa, telefono_contacto, correo_contacto, curso_interes):
    """
    Función para enviar correo de inscripción al curso de capacitación
    """
    # Obtener el nombre legible del curso
    curso_nombre = dict(CURSOS_CAPACITACION).get(curso_interes, curso_interes)
    
    # Manejar teléfono opcional
    telefono_info = telefono_contacto if telefono_contacto else "No proporcionado"
    
    subject = f'Nueva inscripción para curso de capacitación - {nombre_interesado}'
    message = f"""
    Se ha recibido una nueva inscripción para el curso de capacitación:
    
    Nombre del interesado: {nombre_interesado}
    Nombre de la empresa: {nombre_empresa}
    Teléfono de contacto: {telefono_info}
    Correo de contacto: {correo_contacto}
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
        logger.error(f"Error enviando correo de inscripción: {e}")
        return False


def inscripcion_curso(request):
    """
    Vista para el formulario de inscripción al curso de capacitación
    """
    from .models import InscripcionCurso
    
    # Si el usuario está logueado, usar proceso simplificado
    if request.user.is_authenticated:
        curso_id = request.GET.get('curso')
        if curso_id:
            try:
                curso = Curso.objects.get(id=curso_id, activo=True)
                
                # Verificar si ya está inscrito en este curso
                inscripcion_existente = InscripcionCurso.objects.filter(
                    usuario_creado=request.user,
                    curso=curso,
                    estado__in=['pendiente', 'confirmada', 'en_proceso']
                ).first()
                
                if inscripcion_existente:
                    messages.warning(request, f'Ya estás inscrito en el curso "{curso.nombre}".')
                    return redirect('cursos_list')
                
                # Crear inscripción automática para usuario logueado
                inscripcion = InscripcionCurso.objects.create(
                    nombre_interesado=f"{request.user.first_name} {request.user.last_name}".strip(),
                    nombre_empresa=request.user.company_name or "No especificada",
                    telefono_contacto=request.user.phone_number or "",
                    correo_contacto=request.user.email,
                    curso=curso,
                    estado='pendiente',
                    usuario_creado=request.user
                )
                
                # Enviar correo con instrucciones de pago
                if enviar_correo_instrucciones_pago(request, inscripcion):
                    # También enviar notificación al administrador
                    enviar_correo_inscripcion(
                        inscripcion.nombre_interesado,
                        inscripcion.nombre_empresa,
                        inscripcion.telefono_contacto,
                        inscripcion.correo_contacto,
                        curso.nombre
                    )
                    
                    messages.success(request, f'¡Solicitud de inscripción enviada exitosamente para el curso "{curso.nombre}"! Revisa tu correo para las instrucciones de pago.')
                    logger.info(f"Inscripción automática enviada para usuario {request.user.username} al curso {curso.nombre}")
                    return redirect('cursos_list')
                else:
                    messages.error(request, 'Hubo un error al enviar las instrucciones de pago. Por favor, intenta nuevamente.')
                    inscripcion.delete()
                    
            except Curso.DoesNotExist:
                messages.error(request, 'El curso seleccionado no existe.')
                return redirect('cursos_list')
            except Exception as e:
                messages.error(request, f'Error al procesar la inscripción: {str(e)}')
                return redirect('cursos_list')
        else:
            messages.warning(request, 'No se especificó ningún curso para inscribirse.')
            return redirect('cursos_list')
    
    # Proceso normal para usuarios no logueados
    # Obtener el curso pre-seleccionado desde la URL
    curso_id = request.GET.get('curso')
    curso_seleccionado = None
    
    if curso_id:
        try:
            curso_seleccionado = Curso.objects.get(id=curso_id, activo=True)
        except Curso.DoesNotExist:
            messages.warning(request, 'El curso seleccionado no está disponible.')
    
    if request.method == 'POST':
        form = CursoCapacitacionForm(request.POST)
        if form.is_valid():
            nombre_interesado = form.cleaned_data['nombre_interesado']
            nombre_empresa = form.cleaned_data['nombre_empresa']
            telefono_contacto = form.cleaned_data['telefono_contacto']
            correo_contacto = form.cleaned_data['correo_contacto']
            curso_interes = form.cleaned_data['curso_interes']
            
            try:
                # Obtener el curso
                curso = Curso.objects.get(id=curso_interes)
                
                # Crear la inscripción en la base de datos
                inscripcion = InscripcionCurso.objects.create(
                    nombre_interesado=nombre_interesado,
                    nombre_empresa=nombre_empresa,
                    telefono_contacto=telefono_contacto,
                    correo_contacto=correo_contacto,
                    curso=curso,
                    estado='pendiente'
                )
                
                # Enviar correo con instrucciones de pago al interesado
                if enviar_correo_instrucciones_pago(request, inscripcion):
                    # También enviar notificación al administrador
                    enviar_correo_inscripcion(nombre_interesado, nombre_empresa, telefono_contacto, correo_contacto, curso_interes)
                    
                    messages.success(request, '¡Inscripción enviada exitosamente! Revisa tu correo para las instrucciones de pago. Si no lo encuentras, revisa tu spam.')
                    logger.info(f"Inscripción enviada exitosamente a {inscripcion.correo_contacto}")
                    return redirect('inscripcion-curso')
                else:
                    # Si falla el envío del correo, eliminar la inscripción
                    messages.error(request, 'Hubo un error al enviar las instrucciones de pago. Por favor, intenta nuevamente.')
                    logger.error(f"Error al enviar las instrucciones de pago: de {inscripcion.correo_contacto} : {e}")
                    inscripcion.delete()
                    
            except Curso.DoesNotExist:
                messages.error(request, 'El curso seleccionado no existe.')
            except Exception as e:
                messages.error(request, f'Error al procesar la inscripción: {str(e)}')
        else:
            messages.error(request, 'Por favor, corrige los errores en el formulario.')
    else:
        # Si hay un curso pre-seleccionado, inicializar el formulario con ese curso
        if curso_seleccionado:
            form = CursoCapacitacionForm(initial={'curso_interes': curso_seleccionado.id})
        else:
            form = CursoCapacitacionForm()
    
    context = {
        'form': form,
        'curso_seleccionado': curso_seleccionado
    }
    return render(request, 'pages/inscripcion-curso.html', context)


def forum_list(request):
    """
    Vista para listar todos los posts del foro, filtrando por curso si corresponde
    """
    posts = Post.objects.filter(is_active=True)
    cursos_usuario = None
    curso_id = request.GET.get('curso_id')
    curso_especifico = None
    
    if request.user.is_authenticated:
        cursos_usuario = request.user.cursos.all()
        posts = posts.filter(curso__in=cursos_usuario)
        if curso_id:
            posts = posts.filter(curso_id=curso_id)
            try:
                curso_especifico = Curso.objects.get(id=curso_id)
            except Curso.DoesNotExist:
                pass
    else:
        if curso_id:
            posts = posts.filter(curso_id=curso_id)
            try:
                curso_especifico = Curso.objects.get(id=curso_id)
            except Curso.DoesNotExist:
                pass
    
    category_filter = request.GET.get('category')
    if category_filter:
        posts = posts.filter(category=category_filter)
    
    context = {
        'posts': posts,
        'categories': Post.CATEGORY_CHOICES,
        'current_category': category_filter,
        'cursos_usuario': cursos_usuario,
        'curso_id': curso_id,
        'curso_especifico': curso_especifico
    }
    return render(request, 'forum/forum_list.html', context)


def forum_post_detail(request, post_id):
    """
    Vista para ver un post individual y sus comentarios
    """
    try:
        post = Post.objects.get(id=post_id, is_active=True)
        
        # Verificar que el usuario esté inscrito en el curso del post
        if request.user.is_authenticated and post.curso:
            if post.curso not in request.user.cursos.all():
                messages.error(request, 'No tienes acceso a este post. Debes estar inscrito en el curso correspondiente.')
                return redirect('forum_list')
        
        # Incrementar contador de vistas
        post.views += 1
        post.save()
        
        comments = post.comments.filter(is_active=True)
        
        if request.method == 'POST':
            comment_form = CommentForm(request.POST)
            if comment_form.is_valid():
                comment = comment_form.save(commit=False)
                comment.post = post
                comment.author = request.user
                comment.save()
                messages.success(request, 'Comentario publicado exitosamente.')
                return redirect('forum_post_detail', post_id=post.id)
        else:
            comment_form = CommentForm()
        
        context = {
            'post': post,
            'comments': comments,
            'comment_form': comment_form,
            'curso_especifico': post.curso
        }
        return render(request, 'forum/forum_post_detail.html', context)
        
    except Post.DoesNotExist:
        messages.error(request, 'El post no existe.')
        return redirect('forum_list')


@login_required
def forum_create_post(request):
    """
    Vista para crear un nuevo post
    """
    curso_especifico = None
    curso_id = request.GET.get('curso_id')
    
    if curso_id:
        try:
            curso_especifico = Curso.objects.get(id=curso_id)
            if curso_especifico not in request.user.cursos.all():
                messages.error(request, 'No tienes acceso a este curso.')
                return redirect('forum_list')
        except Curso.DoesNotExist:
            messages.error(request, 'Curso no encontrado.')
            return redirect('forum_list')
    
    if request.method == 'POST':
        form = PostForm(request.POST)
        if curso_especifico:
            # Si es un curso específico, no mostrar el campo curso
            form.fields.pop('curso', None)
        else:
            form.fields['curso'].queryset = request.user.cursos.all()
        
        if form.is_valid():
            post = form.save(commit=False)
            post.author = request.user
            if curso_especifico:
                post.curso = curso_especifico
            
            # Limpiar y validar HTML
            content = post.content
            allowed_tags = ['strong', 'em', 'u', 'b', 'i', 'br', 'p', 'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'ul', 'ol', 'li', 'blockquote', 'code', 'pre']
            allowed_attrs = ['class', 'style']
            import bleach
            try:
                content = bleach.clean(content, tags=allowed_tags, attributes=allowed_attrs, strip=True)
            except ImportError:
                import re
                pattern = re.compile(r'<(?!\/?(?:' + '|'.join(allowed_tags) + r')\b)[^>]+>')
                content = pattern.sub('', content)
            post.content = content
            post.save()
            messages.success(request, 'Post creado exitosamente.')
            return redirect('forum_post_detail', post_id=post.id)
    else:
        form = PostForm()
        if curso_especifico:
            # Si es un curso específico, no mostrar el campo curso
            form.fields.pop('curso', None)
        else:
            form.fields['curso'].queryset = request.user.cursos.all()
    
    context = {'form': form, 'curso_especifico': curso_especifico}
    return render(request, 'forum/forum_create_post.html', context)


@login_required
def forum_delete_post(request, post_id):
    """
    Vista para eliminar un post (solo el autor puede eliminarlo)
    """
    try:
        post = Post.objects.get(id=post_id, author=request.user)
        post.is_active = False
        post.save()
        messages.success(request, 'Post eliminado exitosamente.')
    except Post.DoesNotExist:
        messages.error(request, 'No tienes permisos para eliminar este post.')
    
    return redirect('forum_list')


@login_required
def forum_delete_comment(request, comment_id):
    """
    Vista para eliminar un comentario (solo el autor puede eliminarlo)
    """
    try:
        comment = Comment.objects.get(id=comment_id, author=request.user)
        post_id = comment.post.id
        comment.is_active = False
        comment.save()
        messages.success(request, 'Comentario eliminado exitosamente.')
        return redirect('forum_post_detail', post_id=post_id)
    except Comment.DoesNotExist:
        messages.error(request, 'No tienes permisos para eliminar este comentario.')
        return redirect('forum_list')

def test_auth(request):
    """
    Vista de prueba para verificar el estado de autenticación
    """
    context = {
        'user_authenticated': request.user.is_authenticated,
        'user': request.user,
        'session_key': request.session.session_key,
        'session_exists': request.session.session_key is not None,
    }
    return render(request, 'pages/test_auth.html', context)

def test_registration_form(request):
    """
    Vista de prueba para el formulario de registro
    """
    if not settings.DEBUG:
        return HttpResponse("Debug solo disponible en modo desarrollo", status=403)
    
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            # No crear el usuario, solo mostrar que es válido
            return JsonResponse({
                'valid': True,
                'message': 'Formulario válido - Usuario no creado (modo prueba)'
            })
        else:
            return JsonResponse({
                'valid': False,
                'errors': form.errors
            })
    else:
        form = RegistrationForm()
    
    return render(request, 'pages/test_registration.html', {'form': form})

def blog_list(request):
    """
    Vista para listar todos los posts del blog
    """
    posts = BlogPost.objects.filter(is_active=True)
    category_filter = request.GET.get('category')
    if category_filter:
        posts = posts.filter(category=category_filter)
    
    context = {
        'posts': posts,
        'categories': BlogPost.CATEGORY_CHOICES,
        'current_category': category_filter
    }
    return render(request, 'blog/blog_list.html', context)


def blog_post_detail(request, post_id):
    """
    Vista para ver un post individual del blog
    """
    try:
        post = BlogPost.objects.get(id=post_id, is_active=True)
        # Incrementar contador de vistas
        post.views += 1
        post.save()
        
        context = {
            'post': post
        }
        return render(request, 'blog/blog_post_detail.html', context)
        
    except BlogPost.DoesNotExist:
        messages.error(request, 'El artículo no existe.')
        return redirect('blog_list')


@login_required
def blog_create_post(request):
    """
    Vista para crear un nuevo post del blog (solo administradores)
    """
    if not request.user.is_staff:
        messages.error(request, 'No tienes permisos para crear artículos del blog.')
        return redirect('blog_list')
    
    if request.method == 'POST':
        form = BlogPostForm(request.POST, request.FILES)
        if form.is_valid():
            post = form.save(commit=False)
            post.author = request.user
            
            # Limpiar y validar HTML
            content = post.content
            allowed_tags = ['strong', 'em', 'u', 'b', 'i', 'br', 'p', 'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'ul', 'ol', 'li', 'blockquote', 'code', 'pre', 'img']
            allowed_attrs = ['class', 'style', 'src', 'alt', 'width', 'height']
            
            import bleach
            try:
                content = bleach.clean(content, tags=allowed_tags, attributes=allowed_attrs, strip=True)
            except ImportError:
                import re
                pattern = re.compile(r'<(?!\/?(?:' + '|'.join(allowed_tags) + r')\b)[^>]+>')
                content = pattern.sub('', content)
            
            post.content = content
            post.save()
            messages.success(request, 'Artículo publicado exitosamente.')
            return redirect('blog_post_detail', post_id=post.id)
    else:
        form = BlogPostForm()
    
    context = {'form': form}
    return render(request, 'blog/blog_create_post.html', context)


@login_required
def blog_delete_post(request, post_id):
    """
    Vista para eliminar un post del blog (solo administradores)
    """
    if not request.user.is_staff:
        messages.error(request, 'No tienes permisos para eliminar artículos del blog.')
        return redirect('blog_list')
    
    try:
        post = BlogPost.objects.get(id=post_id)
        post.is_active = False
        post.save()
        messages.success(request, 'Artículo eliminado exitosamente.')
    except BlogPost.DoesNotExist:
        messages.error(request, 'El artículo no existe.')
    
    return redirect('blog_list')


@login_required
def curso_detail(request, curso_id):
    """
    Vista para mostrar el detalle completo de un curso
    """
    try:
        curso = Curso.objects.get(id=curso_id, activo=True)
        print(request)
        
        # Verificar que el usuario esté inscrito en el curso
        if curso not in request.user.cursos.all():
            messages.error(request, 'No tienes acceso a este curso. Debes estar inscrito para ver su contenido.')
            return redirect('user_space')
        
        context = {
            'curso': curso,
        }
        return render(request, 'pages/curso_detail.html', context)
        
    except Curso.DoesNotExist:
        messages.error(request, 'El curso no existe o no está disponible.')
        return redirect('user_space')


@login_required
def plataforma_aprendizaje(request, curso_id):
    """
    Vista para la plataforma de aprendizaje de un curso específico
    """
    try:
        curso = Curso.objects.get(id=curso_id, activo=True)
        
        # Verificar que el usuario esté inscrito en el curso
        if curso not in request.user.cursos.all():
            messages.error(request, 'No tienes acceso a este curso. Debes estar inscrito para ver su contenido.')
            return redirect('user_space')
        
        # Obtener la sección activa y acciones desde la URL
        seccion_activa = request.GET.get('seccion', 'inicio')
        action = request.GET.get('action')
        post_id = request.GET.get('post_id')
        
        # Definir el contexto base
        context = {
            'curso': curso,
            'seccion_activa': seccion_activa,
        }
        
        # Si hay una acción específica, manejar según el tipo
        if action == 'crear_post':
            # Cargar el formulario de crear post en el contexto
            from .forms import PostForm
            form = PostForm()
            # Ocultar el campo curso ya que se asigna automáticamente
            form.fields.pop('curso', None)
            context['form'] = form
            context['action'] = 'crear_post'
        elif action == 'ver_post' and post_id:
            # Cargar el post específico en el contexto
            try:
                post = Post.objects.get(id=post_id, curso=curso, is_active=True)
                
                # Manejar envío de comentarios
                if request.method == 'POST':
                    comment_form = CommentForm(request.POST)
                    if comment_form.is_valid():
                        comment = comment_form.save(commit=False)
                        comment.post = post
                        comment.author = request.user
                        comment.save()
                        messages.success(request, 'Comentario publicado exitosamente.')
                        # Redirigir de vuelta al mismo post para evitar reenvío del formulario
                        from django.urls import reverse
                        redirect_url = f"{reverse('plataforma_aprendizaje', kwargs={'curso_id': curso_id})}?seccion=foro&action=ver_post&post_id={post_id}"
                        return HttpResponseRedirect(redirect_url)
                else:
                    comment_form = CommentForm()
                
                # Incrementar contador de vistas solo en GET
                # if request.method == 'GET':
                #     post.views += 1
                #     post.save()
                
                comments = post.comments.filter(is_active=True)
                
                context['post'] = post
                context['comments'] = comments
                context['comment_form'] = comment_form
                context['action'] = 'ver_post'
            except Post.DoesNotExist:
                messages.error(request, 'El post no existe o no está disponible.')
                return redirect('plataforma_aprendizaje', curso_id=curso_id)
        
        return render(request, 'pages/plataforma_aprendizaje.html', context)
        
    except Curso.DoesNotExist:
        messages.error(request, 'El curso no existe o no está disponible.')
        return redirect('user_space')


@login_required
def plataforma_foro(request, curso_id):
    """
    Vista para el foro dentro de la plataforma de aprendizaje
    """
    try:
        curso = Curso.objects.get(id=curso_id, activo=True)
        
        # Verificar que el usuario esté inscrito en el curso
        if curso not in request.user.cursos.all():
            messages.error(request, 'No tienes acceso a este curso. Debes estar inscrito para ver su contenido.')
            return redirect('user_space')
        
        # Obtener posts del curso
        posts = Post.objects.filter(curso=curso, is_active=True).order_by('-created_at')
        
        # Filtros
        category_filter = request.GET.get('category')
        if category_filter:
            posts = posts.filter(category=category_filter)
        
        context = {
            'curso': curso,
            'posts': posts,
            'categories': Post.CATEGORY_CHOICES,
            'current_category': category_filter,
        }
        
        # Si es una petición AJAX, devolver solo el contenido
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            html = render_to_string('pages/plataforma_foro_content.html', context, request=request)
            return JsonResponse({'html': html})
        
        # Si no es AJAX, renderizar la página completa
        return render(request, 'pages/plataforma_foro.html', context)
        
    except Curso.DoesNotExist:
        messages.error(request, 'El curso no existe o no está disponible.')
        return redirect('user_space')


@login_required
def plataforma_foro_post_detail(request, curso_id, post_id):
    """
    Vista para ver un post individual dentro de la plataforma
    """
    try:
        curso = Curso.objects.get(id=curso_id, activo=True)
        
        # Verificar que el usuario esté inscrito en el curso
        if curso not in request.user.cursos.all():
            messages.error(request, 'No tienes acceso a este curso. Debes estar inscrito para ver su contenido.')
            return redirect('user_space')
        
        post = Post.objects.get(id=post_id, curso=curso, is_active=True)
        
        # Incrementar contador de vistas
        post.views += 1
        post.save()
        
        comments = post.comments.filter(is_active=True)
        
        if request.method == 'POST':
            comment_form = CommentForm(request.POST)
            if comment_form.is_valid():
                comment = comment_form.save(commit=False)
                comment.post = post
                comment.author = request.user
                comment.save()
                messages.success(request, 'Comentario publicado exitosamente.')
                return redirect('plataforma_foro_post_detail', curso_id=curso.id, post_id=post.id)
        else:
            comment_form = CommentForm()
        
        context = {
            'curso': curso,
            'post': post,
            'comments': comments,
            'comment_form': comment_form,
        }
        return render(request, 'pages/plataforma_foro_post_detail.html', context)
        
    except (Curso.DoesNotExist, Post.DoesNotExist):
        messages.error(request, 'El curso o post no existe.')
        return redirect('user_space')


@login_required
def plataforma_foro_create_post(request, curso_id):
    """
    Vista para crear un nuevo post dentro de la plataforma
    """
    try:
        curso = Curso.objects.get(id=curso_id, activo=True)
        
        # Verificar que el usuario esté inscrito en el curso
        if curso not in request.user.cursos.all():
            messages.error(request, 'No tienes acceso a este curso. Debes estar inscrito para ver su contenido.')
            return redirect('user_space')
        
        if request.method == 'POST':
            form = PostForm(request.POST)
            if form.is_valid():
                post = form.save(commit=False)
                post.author = request.user
                post.curso = curso
                
                # Limpiar y validar HTML
                content = post.content
                allowed_tags = ['strong', 'em', 'u', 'b', 'i', 'br', 'p', 'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'ul', 'ol', 'li', 'blockquote', 'code', 'pre']
                allowed_attrs = ['class', 'style']
                import bleach
                try:
                    content = bleach.clean(content, tags=allowed_tags, attributes=allowed_attrs, strip=True)
                except ImportError:
                    import re
                    pattern = re.compile(r'<(?!\/?(?:' + '|'.join(allowed_tags) + r')\b)[^>]+>')
                    content = pattern.sub('', content)
                post.content = content
                post.save()
                messages.success(request, 'Post creado exitosamente.')
                from django.urls import reverse
                redirect_url = f"{reverse('plataforma_aprendizaje', kwargs={'curso_id': curso.id})}?seccion=foro"
                return redirect(redirect_url)
        else:
            form = PostForm()
            # Ocultar el campo curso ya que se asigna automáticamente
            form.fields.pop('curso', None)
        
        context = {'form': form, 'curso': curso}
        return render(request, 'pages/plataforma_foro_create_post.html', context)
        
    except Curso.DoesNotExist:
        messages.error(request, 'El curso no existe o no está disponible.')
        return redirect('user_space')


@login_required
def plataforma_foro_delete_post(request, curso_id, post_id):
    """
    Vista para eliminar un post dentro de la plataforma (solo el autor puede eliminarlo)
    """
    try:
        curso = Curso.objects.get(id=curso_id, activo=True)
        
        # Verificar que el usuario esté inscrito en el curso
        if curso not in request.user.cursos.all():
            messages.error(request, 'No tienes acceso a este curso. Debes estar inscrito para ver su contenido.')
            return redirect('user_space')
        
        # Buscar el post y verificar que el usuario sea el autor
        post = Post.objects.get(id=post_id, curso=curso, author=request.user, is_active=True)
        
        # Marcar como inactivo en lugar de eliminar físicamente
        post.is_active = False
        post.save()
        
        messages.success(request, 'Post eliminado exitosamente.')
        
    except Curso.DoesNotExist:
        messages.error(request, 'El curso no existe o no está disponible.')
    except Post.DoesNotExist:
        messages.error(request, 'No tienes permisos para eliminar este post o el post no existe.')
    
    # Redirigir de vuelta a la plataforma del curso en la sección foro
    from django.urls import reverse
    redirect_url = f"{reverse('plataforma_aprendizaje', kwargs={'curso_id': curso_id})}?seccion=foro"
    return redirect(redirect_url)


# @login_required
# def plataforma_foro_delete_comment(request, curso_id, comment_id):
#     """
#     Vista para eliminar un comentario dentro de la plataforma (solo el autor puede eliminarlo)
#     """
#     try:
#         curso = Curso.objects.get(id=curso_id, activo=True)
        
#         # Verificar que el usuario esté inscrito en el curso
#         if curso not in request.user.cursos.all():
#             messages.error(request, 'No tienes acceso a este curso. Debes estar inscrito para ver su contenido.')
#             return redirect('user_space')
        
#         # Buscar el comentario y verificar que el usuario sea el autor
#         comment = Comment.objects.get(id=comment_id, author=request.user, is_active=True)
        
#         # Verificar que el comentario pertenezca a un post del curso
#         if comment.post.curso != curso:
#             messages.error(request, 'No tienes permisos para eliminar este comentario.')
#             return redirect('plataforma_aprendizaje', curso_id=curso_id)
        
#         # Marcar como inactivo en lugar de eliminar físicamente
#         comment.is_active = False
#         comment.save()
        
#         messages.success(request, 'Comentario eliminado exitosamente.')
        
#     except Curso.DoesNotExist:
#         messages.error(request, 'El curso no existe o no está disponible.')
#     except Comment.DoesNotExist:
#         messages.error(request, 'No tienes permisos para eliminar este comentario o el comentario no existe.')
    
#     # Redirigir de vuelta a la plataforma del curso
#     return redirect('plataforma_aprendizaje', curso_id=curso_id)


def cursos_list(request):
    """
    Vista para mostrar todos los cursos de capacitación disponibles
    """
    from .models import InscripcionCurso
    
    cursos_activos = Curso.objects.filter(activo=True).order_by('nombre')
    
    # Si el usuario está logueado, obtener sus inscripciones
    inscripciones_usuario = []
    if request.user.is_authenticated:
        inscripciones_usuario = InscripcionCurso.objects.filter(
            usuario_creado=request.user,
            estado__in=['pendiente', 'confirmada', 'en_proceso']
        ).values_list('curso_id', flat=True)
    
    context = {
        'cursos': cursos_activos,
        'inscripciones_usuario': inscripciones_usuario,
    }
    return render(request, 'pages/cursos_list.html', context)


@login_required
def mi_perfil(request):
    """
    Vista para gestionar el perfil del usuario
    """
    if request.method == 'POST':
        # Obtener datos del formulario
        first_name = request.POST.get('first_name', '')
        last_name = request.POST.get('last_name', '')
        email = request.POST.get('email', '')
        company_name = request.POST.get('company_name', '')
        
        # Validar que el email no esté en uso por otro usuario
        if email != request.user.email:
            if User.objects.filter(email=email).exclude(id=request.user.id).exists():
                messages.error(request, 'Este correo electrónico ya está en uso por otro usuario.')
                return redirect('mi_perfil')
        
        # Actualizar datos del usuario
        request.user.first_name = first_name
        request.user.last_name = last_name
        request.user.email = email
        request.user.company_name = company_name
        
        # Manejar subida de foto de perfil
        if 'profile_photo' in request.FILES:
            request.user.profile_photo = request.FILES['profile_photo']
        
        # Manejar eliminación de foto de perfil
        if request.POST.get('delete_photo') == 'true':
            if request.user.profile_photo:
                request.user.profile_photo.delete(save=False)
            request.user.profile_photo = None
        
        request.user.save()
        messages.success(request, 'Perfil actualizado exitosamente.')
        return redirect('mi_perfil')
    
    # Obtener cursos completados del usuario (puedes ajustar la lógica según tu modelo)
    cursos_completados = request.user.cursos.all()  # Ajusta según tu lógica de cursos completados
    
    context = {
        'cursos_completados': cursos_completados,
    }
    return render(request, 'pages/mi_perfil.html', context)


def curso_detail_public(request, curso_id):
    """
    Vista pública para mostrar el detalle de un curso (sin restricción de login)
    """
    from .models import InscripcionCurso
    
    try:
        curso = Curso.objects.get(id=curso_id, activo=True)
        
        # Verificar si el usuario está inscrito en este curso
        usuario_inscrito = False
        if request.user.is_authenticated:
            usuario_inscrito = InscripcionCurso.objects.filter(
                usuario_creado=request.user,
                curso=curso,
                estado__in=['pendiente', 'confirmada', 'en_proceso']
            ).exists()
        
        context = {
            'curso': curso,
            'usuario_inscrito': usuario_inscrito,
        }
        return render(request, 'pages/curso_detail_public.html', context)
        
    except Curso.DoesNotExist:
        messages.error(request, 'El curso no existe o no está disponible.')
        return redirect('cursos_list')


def custom_404(request, exception):
    """
    Vista personalizada para error 404
    """
    return render(request, 'pages/404.html', status=404)


def custom_500(request):
    """
    Vista personalizada para error 500
    """
    return render(request, 'pages/500.html', status=500)

@login_required
def extend_session(request):
    """
    Vista para extender la sesión del usuario
    """
    if request.method == 'POST':
        # Actualizar la última actividad en la sesión
        request.session['last_activity'] = time.time()
        request.session.modified = True
        return JsonResponse({'status': 'success'})
    return JsonResponse({'status': 'error'}, status=400)


@login_required
def admin_inscripciones(request):
    """
    Panel de administrador para gestionar inscripciones a cursos
    """
    if not request.user.is_staff:
        messages.error(request, 'No tienes permisos para acceder a esta sección.')
        return redirect('index')
    
    # Obtener todas las inscripciones ordenadas por fecha
    inscripciones = InscripcionCurso.objects.all()
    
    # Filtros
    estado_filter = request.GET.get('estado')
    curso_filter = request.GET.get('curso')
    
    if estado_filter:
        inscripciones = inscripciones.filter(estado=estado_filter)
    
    if curso_filter:
        inscripciones = inscripciones.filter(curso_id=curso_filter)
    
    # Obtener cursos para el filtro
    cursos = Curso.objects.filter(activo=True)
    
    context = {
        'inscripciones': inscripciones,
        'cursos': cursos,
        'estados': InscripcionCurso.ESTADO_CHOICES,
        'estado_filter': estado_filter,
        'curso_filter': curso_filter,
    }
    
    return render(request, 'admin/inscripciones_list.html', context)


@login_required
def admin_inscripcion_detail(request, inscripcion_id):
    """
    Vista detallada de una inscripción específica
    """
    if not request.user.is_staff:
        messages.error(request, 'No tienes permisos para acceder a esta sección.')
        return redirect('index')
    
    try:
        inscripcion = InscripcionCurso.objects.get(id=inscripcion_id)
    except InscripcionCurso.DoesNotExist:
        messages.error(request, 'La inscripción no existe.')
        return redirect('admin-inscripciones')
    
    context = {
        'inscripcion': inscripcion,
    }
    
    return render(request, 'admin/inscripcion_detail.html', context)


#FIXME: No eiste validacion de que el usuario no exista
@login_required
def admin_marcar_pagado(request, inscripcion_id):
    """
    Marcar una inscripción como pagada y crear el usuario
    """
    if not request.user.is_staff:
        messages.error(request, 'No tienes permisos para realizar esta acción.')
        return JsonResponse({'success': False, 'message': 'Sin permisos'})
    
    try:
        inscripcion = InscripcionCurso.objects.get(id=inscripcion_id)
        
        if inscripcion.estado == 'pendiente':
            # Marcar como pagado y crear usuario
            user, password_temp = inscripcion.marcar_como_pagado()
            
            if user and password_temp:
                # Enviar correo de bienvenida
                
                if enviar_correo_bienvenida(request, user, password_temp, inscripcion.curso.nombre) and crear_direccion_gryphos(request, user, password_temp):
                    messages.success(request, f'Inscripción marcada como pagada. Usuario creado: {user.username}')
                    logger.info(f"Correo de bienvenida enviado exitosamente a {user.email}")
                else:
                    messages.warning(request, f'Usuario creado pero error al enviar correo de bienvenida. Usuario: {user.username}, Contraseña: {password_temp}')
                    logger.error(f"Error al enviar correo de bienvenida: {e}")
                
                return JsonResponse({
                    'success': True, 
                    'message': 'Inscripción marcada como pagada',
                    'username': user.username
                })
            else:
                return JsonResponse({
                    'success': False, 
                    'message': 'Error al crear el usuario'
                })
        else:
            return JsonResponse({
                'success': False, 
                'message': 'La inscripción ya no está pendiente'
            })
            
    except InscripcionCurso.DoesNotExist:
        return JsonResponse({
            'success': False, 
            'message': 'Inscripción no encontrada'
        })
    except Exception as e:
        return JsonResponse({
            'success': False, 
            'message': f'Error: {str(e)}'
        })


@login_required
def admin_cambiar_estado(request, inscripcion_id):
    """
    Cambiar el estado de una inscripción
    """
    if not request.user.is_staff:
        messages.error(request, 'No tienes permisos para realizar esta acción.')
        return JsonResponse({'success': False, 'message': 'Sin permisos'})
    
    if request.method == 'POST':
        nuevo_estado = request.POST.get('estado')
        observaciones = request.POST.get('observaciones', '')
        
        if nuevo_estado not in dict(InscripcionCurso.ESTADO_CHOICES):
            return JsonResponse({
                'success': False, 
                'message': 'Estado inválido'
            })
        
        try:
            inscripcion = InscripcionCurso.objects.get(id=inscripcion_id)
            inscripcion.estado = nuevo_estado
            inscripcion.observaciones = observaciones
            inscripcion.save()
            
            messages.success(request, f'Estado de inscripción actualizado a: {inscripcion.get_estado_display()}')
            return JsonResponse({
                'success': True, 
                'message': 'Estado actualizado correctamente'
            })
            
        except InscripcionCurso.DoesNotExist:
            return JsonResponse({
                'success': False, 
                'message': 'Inscripción no encontrada'
            })
        except Exception as e:
            return JsonResponse({
                'success': False, 
                'message': f'Error: {str(e)}'
            })
    
    return JsonResponse({
        'success': False, 
        'message': 'Método no permitido'
    })


@login_required
def admin_reenviar_correo(request, inscripcion_id):
    """
    Vista para reenviar el correo de instrucciones de pago
    """
    if not request.user.is_staff:
        messages.error(request, 'No tienes permisos para realizar esta acción.')
        return JsonResponse({'success': False, 'message': 'Sin permisos'})
    
    if request.method == 'POST':
        try:
            inscripcion = InscripcionCurso.objects.get(id=inscripcion_id)
            
            # Reenviar correo de instrucciones de pago
            if enviar_correo_instrucciones_pago(request, inscripcion):
                #messages.success(request, f'Correo de instrucciones de pago reenviado exitosamente a {inscripcion.correo_contacto}')
                logger.info(f"Correo de instrucciones de pago reenviado exitosamente a {inscripcion.correo_contacto}")
                return JsonResponse({
                    'success': True, 
                    'message': f'Correo reenviado exitosamente a {inscripcion.correo_contacto}'
                })
            else:
                messages.error(request, 'Error al reenviar el correo de instrucciones de pago')
                return JsonResponse({
                    'success': False, 
                    'message': 'Error al reenviar el correo de instrucciones de pago'
                })
                
        except InscripcionCurso.DoesNotExist:
            return JsonResponse({
                'success': False, 
                'message': 'Inscripción no encontrada'
            })
        except Exception as e:
            logger.error(f"Error al reenviar correo: {e}")
            return JsonResponse({
                'success': False, 
                'message': f'Error al reenviar correo: {str(e)}'
            })
    
    return JsonResponse({
        'success': False, 
        'message': 'Método no permitido'
    })

def crear_direccion_gryphos(request, user, password_temp):
    url = "https://mail.gryphos.cl/api/v1/add/mailbox"
    headers = {
        "Accept": "application/json",
        "X-API-Key": f"{settings.API_KEY_MAILCOW}",
        "Content-Type": "application/json"
    }
    data = {
    "active": "1",
    "domain": "gryphos.cl",
    "local_part": user.username,
    "name": user.get_full_name() or user.username,
    "authsource": "mailcow",
    "password": password_temp,
    "password2": password_temp,
    "quota": "3072",
    "force_pw_update": "0",
    "tls_enforce_in": "1",
    "tls_enforce_out": "1",
    "tags": [
        "corporativo"
    ]
    }
    try:
        response = requests.post(url, headers=headers, json=data)
        logger.info(f"Dirección de correo creada exitosamente: {response.json()}")
        return True
    except Exception as e:
        messages.error(request, f"Error al crear la dirección de correo: {e}")
        logger.error(f"Error al crear la dirección de correo: {e}")
        return False


def generate_jitsi_token(request, room_name=None, user=None):
    """
    Genera un token JWT para Jitsi Meet
    
    Args:
        request: HttpRequest object
        room_name: Nombre específico de la sala (opcional)
        user: Usuario específico (opcional, por defecto usa request.user)
    
    Returns:
        JsonResponse con el token JWT
    """
    logger.info(f"Iniciando generación de JWT - Usuario: {request.user.username}, Sala: {room_name or 'general'}")
    
    if not request.user.is_authenticated:
        logger.warning(f"Intento de generar JWT sin autenticación desde IP: {request.META.get('REMOTE_ADDR', 'desconocida')}")
        return JsonResponse({"error": "No autenticado"}, status=403)

    # Usar el usuario proporcionado o el usuario de la request
    current_user = user or request.user
    logger.debug(f"Generando JWT para usuario: {current_user.username} (staff: {current_user.is_staff})")
    
    try:
        payload = {
            "iss": "gryphos",  # Debe coincidir con el issuer en Jitsi
            "aud": "jitsi",  # Audience estándar para Jitsi
            "sub": "meet.gryphos.cl",
            "room": room_name or "*",  # Sala específica o cualquier sala
            "exp": datetime.utcnow() + timedelta(hours=2),  # Expira en 2 horas
            "context": {
                "user": {
                    "name": current_user.get_full_name() or current_user.username,
                    "email": current_user.email,
                    "avatar": getattr(current_user, 'profile', None) and current_user.profile.avatar_url or "",
                    "moderator": current_user.is_staff,  # Los staff son moderadores
                },
            }
        }
        
        logger.debug(f"Payload JWT generado para sala: {payload['room']}")
        
        # Log detallado de tiempos
        import pytz
        
        # Obtener tiempo actual en UTC
        now_utc = datetime.utcnow()
        exp_utc = payload['exp']
        
        # Convertir a zona horaria local para logs
        try:
            local_tz = pytz.timezone('America/Santiago')  # Zona horaria de Chile
            now_local = now_utc.replace(tzinfo=pytz.UTC).astimezone(local_tz)
            exp_local = exp_utc.replace(tzinfo=pytz.UTC).astimezone(local_tz)
        except:
            now_local = now_utc
            exp_local = exp_utc
        
        logger.info(f"=== TIEMPOS JWT ===")
        logger.info(f"Tiempo actual (UTC): {now_utc}")
        logger.info(f"Tiempo actual (Local): {now_local}")
        logger.info(f"Tiempo expiración (UTC): {exp_utc}")
        logger.info(f"Tiempo expiración (Local): {exp_local}")
        logger.info(f"Duración del token: {exp_utc - now_utc}")
        logger.info(f"==================")
        
        token = jwt.encode(payload, settings.JITSI_JWT_SECRET, algorithm="HS256")
        logger.info(f"JWT generado exitosamente para usuario {current_user.username} en sala {payload['room']}")
        
        # Log detallado del token
        logger.info(f"=== TOKEN JWT COMPLETO ===")
        logger.info(f"Token: {token}")
        logger.info(f"Payload: {payload}")
        logger.info(f"Secret key length: {len(settings.JITSI_JWT_SECRET)}")
        logger.info(f"==========================")
        
        return JsonResponse({"token": token})
        
    except Exception as e:
        logger.error(f"Error generando JWT para usuario {current_user.username}: {str(e)}")
        logger.error(f"Tipo de error: {type(e).__name__}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return JsonResponse({"error": "Error interno del servidor"}, status=500)


@login_required
def join_meeting(request, videollamada_id):
    """
    Vista para unirse a una videollamada específica con JWT token
    """
    from .models import Videollamada
    
    logger.info(f"Intento de unirse a videollamada {videollamada_id} - Usuario: {request.user.username}")
    logger.debug(f"IP del usuario: {request.META.get('REMOTE_ADDR', 'desconocida')}")
    
    try:
        # Obtener la videollamada
        logger.debug(f"Buscando videollamada con ID: {videollamada_id}")
        videollamada = Videollamada.objects.get(id=videollamada_id, activa=True)
        logger.debug(f"Videollamada encontrada: {videollamada} (Curso: {videollamada.curso.nombre})")
        
        # Verificar que el usuario esté inscrito en el curso de la videollamada
        logger.debug(f"Verificando acceso del usuario {request.user.username} al curso {videollamada.curso.nombre}")
        if videollamada.curso not in request.user.cursos.all():
            logger.warning(f"Acceso denegado: Usuario {request.user.username} no está inscrito en el curso {videollamada.curso.nombre}")
            messages.error(request, 'No tienes acceso a esta videollamada. Debes estar inscrito en el curso correspondiente.')
            return redirect('user_space')
        
        logger.debug(f"Acceso verificado: Usuario {request.user.username} tiene acceso al curso {videollamada.curso.nombre}")
        
        # Verificar que la videollamada esté activa ahora
        logger.debug(f"Verificando si la videollamada {videollamada_id} está activa ahora")
        if not videollamada.esta_activa_ahora():
            logger.warning(f"Videollamada {videollamada_id} no está activa en este momento para usuario {request.user.username}")
            messages.warning(request, 'Esta videollamada no está activa en este momento.')
            return redirect('user_space')
        
        logger.debug(f"Videollamada {videollamada_id} está activa y disponible")
        
        # Verificar que tenga un enlace configurado
        logger.debug(f"Verificando enlace de videollamada {videollamada_id}")
        if not videollamada.link_videollamada:
            logger.error(f"Videollamada {videollamada_id} no tiene enlace configurado")
            messages.error(request, 'Esta videollamada no tiene un enlace configurado.')
            return redirect('user_space')
        
        logger.debug(f"Enlace de videollamada {videollamada_id} verificado: {videollamada.link_videollamada}")
        
        # Generar JWT token para la videollamada usando la función existente
        try:
            # Extraer el nombre de la sala de la URL de la videollamada
            from urllib.parse import urlparse
            parsed_url = urlparse(videollamada.link_videollamada)
            # Obtener la última parte de la URL (después del último /)
            room_name = parsed_url.path.strip('/').split('/')[-1]
            logger.debug(f"URL de videollamada: {videollamada.link_videollamada}")
            logger.debug(f"Nombre de sala extraído: {room_name}")
            
            # Usar la función generate_jitsi_token para generar el token
            logger.debug(f"Llamando a generate_jitsi_token para sala {room_name}")
            token_response = generate_jitsi_token(request, room_name=room_name)
            
            if token_response.status_code != 200:
                logger.error(f"Error generando JWT para videollamada {videollamada_id}: {token_response.content}")
                messages.error(request, 'Error al generar el token de acceso a la videollamada.')
                return redirect('user_space')
            
            logger.debug(f"JWT generado exitosamente para videollamada {videollamada_id}")
            
            # Extraer el token del response
            import json
            token_data = json.loads(token_response.content)
            token = token_data.get('token')
            
            if not token:
                logger.error(f"No se pudo obtener el token JWT para videollamada {videollamada_id}")
                messages.error(request, 'Error al generar el token de acceso a la videollamada.')
                return redirect('user_space')
            
            logger.debug(f"Token JWT extraído exitosamente para videollamada {videollamada_id}")
            
            # Log del tiempo de procesamiento
            from datetime import datetime
            processing_time = datetime.utcnow()
            logger.info(f"=== PROCESAMIENTO JWT ===")
            logger.info(f"Tiempo de procesamiento: {processing_time}")
            logger.info(f"Token extraído y listo para uso")
            logger.info(f"Token completo: {token}")
            logger.info(f"========================")
            
            # Construir la URL de la videollamada con el token
            base_url = videollamada.link_videollamada.rstrip('/')
            logger.debug(f"URL base de videollamada: {base_url}")
            
            # Si la URL ya tiene parámetros, agregar el token, si no, agregar como primer parámetro
            if '?' in base_url:
                meeting_url = f"{base_url}&jwt={token}"
            else:
                meeting_url = f"{base_url}?jwt={token}"
            
            logger.debug(f"URL final de videollamada construida: {meeting_url[:100]}...")
            
            # Log de la acción exitosa con tiempo
            redirect_time = datetime.utcnow()
            logger.info(f"Usuario {request.user.username} se unió exitosamente a videollamada {videollamada.id} del curso {videollamada.curso.nombre}")
            logger.info(f"Tiempo de redirección: {redirect_time}")
            logger.info(f"Tiempo total de procesamiento: {redirect_time - processing_time}")
            logger.info(f"Redirigiendo a: {meeting_url}")
            
            # Redirigir a la videollamada
            return redirect(meeting_url)
            
        except Exception as e:
            logger.error(f"Error generando JWT para videollamada {videollamada_id}: {str(e)}")
            messages.error(request, 'Error al generar el token de acceso a la videollamada.')
            return redirect('user_space')
            
    except Videollamada.DoesNotExist:
        logger.warning(f"Videollamada {videollamada_id} no encontrada para usuario {request.user.username}")
        messages.error(request, 'Videollamada no encontrada.')
        return redirect('user_space')
    except Exception as e:
        logger.error(f"Error inesperado al unirse a videollamada {videollamada_id}: {str(e)}")
        messages.error(request, 'Error inesperado al acceder a la videollamada.')
        return redirect('user_space')

@login_required
def plataforma_foro_ajax(request, curso_id):
    """
    Vista AJAX para cargar el contenido del foro dinámicamente
    """
    try:
        curso = Curso.objects.get(id=curso_id, activo=True)
        
        # Verificar que el usuario esté inscrito en el curso
        if curso not in request.user.cursos.all():
            return JsonResponse({'error': 'No tienes acceso a este curso'}, status=403)
        
        # Verificar si es una acción específica
        action = request.GET.get('action')
        
        if action == 'crear_post':
            # Cargar formulario de crear post
            from .forms import PostForm
            form = PostForm()
            # Ocultar el campo curso ya que se asigna automáticamente
            form.fields.pop('curso', None)
            
            context = {
                'curso': curso,
                'form': form,
            }
            
            html = render_to_string('pages/plataforma_foro_create_form.html', context, request=request)
            return JsonResponse({'html': html})
        
        elif action == 'ver_post':
            # Cargar post específico
            post_id = request.GET.get('post_id')
            if post_id:
                try:
                    post = Post.objects.get(id=post_id, curso=curso, is_active=True)
                    # Incrementar contador de vistas
                    post.views += 1
                    post.save()
                    
                    comments = post.comments.filter(is_active=True)
                    comment_form = CommentForm()
                    
                    context = {
                        'curso': curso,
                        'post': post,
                        'comments': comments,
                        'comment_form': comment_form,
                    }
                    
                    html = render_to_string('pages/plataforma_foro_post_detail_content.html', context, request=request)
                    return JsonResponse({'html': html})
                except Post.DoesNotExist:
                    return JsonResponse({'error': 'El post no existe'}, status=404)
            else:
                return JsonResponse({'error': 'ID de post no proporcionado'}, status=400)
        
        # Obtener posts del curso
        posts = Post.objects.filter(curso=curso, is_active=True).order_by('-created_at')
        
        # Filtros
        category_filter = request.GET.get('category')
        if category_filter:
            posts = posts.filter(category=category_filter)
        
        context = {
            'curso': curso,
            'posts': posts,
            'categories': Post.CATEGORY_CHOICES,
            'current_category': category_filter,
        }
        
        # Renderizar solo el contenido del foro
        html = render_to_string('pages/plataforma_foro_content.html', context, request=request)
        return JsonResponse({'html': html})
        
    except Curso.DoesNotExist:
        return JsonResponse({'error': 'El curso no existe'}, status=404)

# ============================================================================
# VISTAS DEL SISTEMA DE CALIFICACIONES
# ============================================================================

@login_required
def plataforma_calificaciones(request, curso_id):
    """
    Vista principal de calificaciones para la plataforma de aprendizaje
    """
    curso = get_object_or_404(Curso, id=curso_id)
    
    # Verificar que el usuario esté inscrito en el curso
    if not request.user.cursos.filter(id=curso_id).exists():
        messages.error(request, 'No tienes acceso a este curso.')
        return redirect('user_space')
    
    context = {
        'curso': curso,
        'user': request.user,
    }
    
    if request.user.is_staff:
        # Vista para Staff/Admin
        evaluaciones = Evaluacion.objects.filter(curso=curso).order_by('-fecha_creacion')
        context['evaluaciones'] = evaluaciones
        
        # Estadísticas generales del curso
        calificaciones_curso = Calificacion.objects.filter(evaluacion__curso=curso, nota__isnull=False)
        if calificaciones_curso.exists():
            estadisticas = {
                'promedio_general': calificaciones_curso.aggregate(Avg('nota'))['nota__avg'],
                'nota_minima': calificaciones_curso.aggregate(Min('nota'))['nota__min'],
                'nota_maxima': calificaciones_curso.aggregate(Max('nota'))['nota__max'],
                'total_estudiantes': curso.usuarios.filter(is_staff=False, is_superuser=False).count(),
            }
            context['estadisticas'] = estadisticas
        
    else:
        # Vista para Estudiantes
        calificaciones_usuario = Calificacion.objects.filter(
            evaluacion__curso=curso,
            estudiante=request.user
        ).order_by('-fecha_calificacion')
        context['calificaciones_usuario'] = calificaciones_usuario
        
        # Estadísticas personales del estudiante
        calificaciones_con_nota = calificaciones_usuario.filter(nota__isnull=False)
        if calificaciones_con_nota.exists():
            estadisticas_estudiante = {
                'promedio_personal': calificaciones_con_nota.aggregate(Avg('nota'))['nota__avg'],
                'nota_minima': calificaciones_con_nota.aggregate(Min('nota'))['nota__min'],
                'nota_maxima': calificaciones_con_nota.aggregate(Max('nota'))['nota__max'],
                'evaluaciones_calificadas': calificaciones_con_nota.count(),
                'total_evaluaciones': Evaluacion.objects.filter(curso=curso).count(),
            }
            context['estadisticas_estudiante'] = estadisticas_estudiante
        
        # Promedios por tipo de evaluación
        promedios_por_tipo = {}
        for calificacion in calificaciones_con_nota:
            tipo = calificacion.evaluacion.get_tipo_display()
            if tipo not in promedios_por_tipo:
                promedios_por_tipo[tipo] = {
                    'notas': [],
                    'ponderaciones': []
                }
            promedios_por_tipo[tipo]['notas'].append(calificacion.nota)
            promedios_por_tipo[tipo]['ponderaciones'].append(calificacion.evaluacion.ponderacion)
        
        # Calcular promedios
        for tipo, datos in promedios_por_tipo.items():
            if datos['notas']:
                datos['promedio'] = sum(datos['notas']) / len(datos['notas'])
                datos['ponderacion_promedio'] = sum(datos['ponderaciones']) / len(datos['ponderaciones'])
        
        context['promedios_por_tipo'] = promedios_por_tipo
    
    return render(request, 'pages/plataforma_calificaciones.html', context)

@login_required
def crear_evaluacion(request, curso_id):
    """
    Vista para crear una nueva evaluación (solo staff/admin)
    """
    curso = get_object_or_404(Curso, id=curso_id)
    
    # Verificar permisos
    if not request.user.is_staff:
        messages.error(request, 'No tienes permisos para crear evaluaciones.')
        return redirect('plataforma_calificaciones', curso_id=curso_id)
    
    if request.method == 'POST':
        form = EvaluacionForm(request.POST)
        if form.is_valid():
            evaluacion = form.save(commit=False)
            evaluacion.curso = curso
            evaluacion.creado_por = request.user
            evaluacion.save()
            messages.success(request, f'Evaluación "{evaluacion.nombre}" creada exitosamente.')
            return redirect('plataforma_calificaciones', curso_id=curso_id)
    else:
        form = EvaluacionForm()
    
    context = {
        'curso': curso,
        'form': form,
        'user': request.user,
    }
    return render(request, 'pages/crear_evaluacion.html', context)

@login_required
def calificar_estudiante(request, curso_id, evaluacion_id):
    """
    Vista para calificar estudiantes en una evaluación específica (solo staff/admin)
    """
    curso = get_object_or_404(Curso, id=curso_id)
    evaluacion = get_object_or_404(Evaluacion, id=evaluacion_id, curso=curso)
    
    # Verificar permisos
    if not request.user.is_staff:
        messages.error(request, 'No tienes permisos para calificar estudiantes.')
        return redirect('plataforma_calificaciones', curso_id=curso_id)
    
    # Obtener estudiantes del curso (no staff/admin)
    estudiantes = User.objects.filter(
        cursos=curso,
        is_staff=False,
        is_superuser=False
    ).order_by('first_name', 'last_name', 'username')
    
    if request.method == 'POST':
        form = CalificacionForm(request.POST, curso=curso)
        if form.is_valid():
            calificacion = form.save(commit=False)
            calificacion.evaluacion = evaluacion
            calificacion.calificado_por = request.user
            
            # Verificar que no exista ya una calificación para este estudiante en esta evaluación
            calificacion_existente = Calificacion.objects.filter(
                evaluacion=evaluacion,
                estudiante=calificacion.estudiante
            ).first()
            
            if calificacion_existente:
                # Actualizar calificación existente
                calificacion_existente.nota = calificacion.nota
                calificacion_existente.retroalimentacion = calificacion.retroalimentacion
                calificacion_existente.calificado_por = request.user
                calificacion_existente.save()
                messages.success(request, f'Calificación actualizada para {calificacion.estudiante.get_full_name()}.')
            else:
                # Crear nueva calificación
                calificacion.save()
                messages.success(request, f'Calificación registrada para {calificacion.estudiante.get_full_name()}.')
            
            return redirect('plataforma_calificaciones', curso_id=curso_id)
    else:
        form = CalificacionForm(curso=curso)
    
    context = {
        'curso': curso,
        'evaluacion': evaluacion,
        'form': form,
        'estudiantes': estudiantes,
        'user': request.user,
    }
    return render(request, 'pages/calificar_estudiante.html', context)

@login_required
def ver_calificacion_detalle(request, curso_id, calificacion_id):
    """
    Vista para ver el detalle de una calificación específica
    """
    curso = get_object_or_404(Curso, id=curso_id)
    calificacion = get_object_or_404(Calificacion, id=calificacion_id)
    
    # Verificar que el usuario tenga acceso a esta calificación
    if not request.user.is_staff and calificacion.estudiante != request.user:
        messages.error(request, 'No tienes acceso a esta calificación.')
        return redirect('plataforma_calificaciones', curso_id=curso_id)
    
    # Verificar que la calificación pertenezca al curso
    if calificacion.evaluacion.curso != curso:
        messages.error(request, 'La calificación no pertenece a este curso.')
        return redirect('plataforma_calificaciones', curso_id=curso_id)
    
    context = {
        'curso': curso,
        'calificacion': calificacion,
        'user': request.user,
    }
    return render(request, 'pages/calificacion_detalle.html', context)

@login_required
def estadisticas_curso(request, curso_id):
    """
    Vista para ver estadísticas detalladas del curso (solo staff/admin)
    """
    curso = get_object_or_404(Curso, id=curso_id)
    
    # Verificar permisos
    if not request.user.is_staff:
        messages.error(request, 'No tienes permisos para ver estadísticas del curso.')
        return redirect('plataforma_calificaciones', curso_id=curso_id)
    
    # Obtener todas las calificaciones del curso
    calificaciones = Calificacion.objects.filter(evaluacion__curso=curso, nota__isnull=False)
    
    # Estadísticas generales
    estadisticas = {
        'total_estudiantes': curso.usuarios.filter(is_staff=False, is_superuser=False).count(),
        'total_evaluaciones': Evaluacion.objects.filter(curso=curso).count(),
        'total_calificaciones': calificaciones.count(),
    }
    
    if calificaciones.exists():
        estadisticas.update({
            'promedio_general': calificaciones.aggregate(Avg('nota'))['nota__avg'],
            'nota_minima': calificaciones.aggregate(Min('nota'))['nota__min'],
            'nota_maxima': calificaciones.aggregate(Max('nota'))['nota__max'],
        })
    
    # Estadísticas por evaluación
    evaluaciones = Evaluacion.objects.filter(curso=curso).order_by('fecha_evaluacion')
    estadisticas_evaluaciones = []
    
    for evaluacion in evaluaciones:
        calificaciones_eval = calificaciones.filter(evaluacion=evaluacion)
        stats = {
            'evaluacion': evaluacion,
            'total_calificaciones': calificaciones_eval.count(),
            'promedio': calificaciones_eval.aggregate(Avg('nota'))['nota__avg'] if calificaciones_eval.exists() else None,
            'nota_minima': calificaciones_eval.aggregate(Min('nota'))['nota__min'] if calificaciones_eval.exists() else None,
            'nota_maxima': calificaciones_eval.aggregate(Max('nota'))['nota__max'] if calificaciones_eval.exists() else None,
        }
        estadisticas_evaluaciones.append(stats)
    
    # Estadísticas por estudiante
    estudiantes = curso.usuarios.filter(is_staff=False, is_superuser=False).order_by('first_name', 'last_name')
    estadisticas_estudiantes = []
    
    for estudiante in estudiantes:
        calificaciones_est = calificaciones.filter(estudiante=estudiante)
        stats = {
            'estudiante': estudiante,
            'total_calificaciones': calificaciones_est.count(),
            'promedio': calificaciones_est.aggregate(Avg('nota'))['nota__avg'] if calificaciones_est.exists() else None,
            'nota_minima': calificaciones_est.aggregate(Min('nota'))['nota__min'] if calificaciones_est.exists() else None,
            'nota_maxima': calificaciones_est.aggregate(Max('nota'))['nota__max'] if calificaciones_est.exists() else None,
        }
        estadisticas_estudiantes.append(stats)
    
    context = {
        'curso': curso,
        'estadisticas': estadisticas,
        'estadisticas_evaluaciones': estadisticas_evaluaciones,
        'estadisticas_estudiantes': estadisticas_estudiantes,
        'user': request.user,
    }
    return render(request, 'pages/estadisticas_curso.html', context)