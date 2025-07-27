from django.shortcuts import render, redirect
import time
from .forms import LoginForm, RegistrationForm, UserPasswordResetForm, UserSetPasswordForm, UserPasswordChangeForm, CursoCapacitacionForm, CURSOS_CAPACITACION, PostForm, CommentForm, BlogPostForm
from django.contrib.auth import logout
from django.contrib.auth import views as auth_views
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from .models import RegistrationLink, Post, Comment, Curso, BlogPost, InscripcionCurso
from django.http import JsonResponse, HttpResponse
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
        form = CursoCapacitacionForm()
    
    context = {'form': form}
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
        messages.error(request, 'La videollamada no existe o no está disponible.')
        return redirect('user_space')
    except Exception as e:
        logger.error(f"Error en join_meeting para usuario {request.user.username}: {str(e)}")
        messages.error(request, 'Error al acceder a la videollamada.')
        return redirect('user_space')


@login_required
def test_meeting_jwt(request, videollamada_id):
    """
    Vista de prueba para verificar la generación de JWT para videollamadas
    """
    from .models import Videollamada
    
    logger.info(f"Prueba de JWT solicitada para videollamada {videollamada_id} - Usuario: {request.user.username}")
    
    if not settings.DEBUG:
        logger.warning(f"Intento de acceso a test_meeting_jwt en producción desde IP: {request.META.get('REMOTE_ADDR', 'desconocida')}")
        return HttpResponse("Debug solo disponible en modo desarrollo", status=403)
    
    try:
        logger.debug(f"Buscando videollamada con ID: {videollamada_id} para prueba")
        videollamada = Videollamada.objects.get(id=videollamada_id)
        logger.debug(f"Videollamada encontrada para prueba: {videollamada} (Curso: {videollamada.curso.nombre})")
        
        # Verificar acceso
        logger.debug(f"Verificando acceso del usuario {request.user.username} al curso {videollamada.curso.nombre} para prueba")
        if videollamada.curso not in request.user.cursos.all():
            logger.warning(f"Acceso denegado en prueba: Usuario {request.user.username} no está inscrito en el curso {videollamada.curso.nombre}")
            return JsonResponse({
                'error': 'No tienes acceso a esta videollamada'
            }, status=403)
        
        logger.debug(f"Acceso verificado para prueba: Usuario {request.user.username} tiene acceso al curso {videollamada.curso.nombre}")
        
        # Generar JWT usando la función existente
        room_name = f"curso_{videollamada.curso.id}_{videollamada.id}"
        logger.debug(f"Generando JWT de prueba para sala: {room_name}")
        
        # Usar la función generate_jitsi_token
        logger.debug(f"Llamando a generate_jitsi_token para prueba en sala {room_name}")
        token_response = generate_jitsi_token(request, room_name=room_name)
        
        if token_response.status_code != 200:
            logger.error(f"Error generando JWT de prueba para videollamada {videollamada_id}: {token_response.content}")
            return JsonResponse({
                'error': 'Error generando JWT'
            }, status=500)
        
        logger.debug(f"JWT de prueba generado exitosamente para videollamada {videollamada_id}")
        
        # Extraer el token del response
        import json
        token_data = json.loads(token_response.content)
        token = token_data.get('token')
        
        if not token:
            logger.error(f"No se pudo obtener el token JWT de prueba para videollamada {videollamada_id}")
            return JsonResponse({
                'error': 'No se pudo obtener el token JWT'
            }, status=500)
        
        logger.debug(f"Token JWT de prueba extraído exitosamente para videollamada {videollamada_id}")
        
        # Construir URL
        base_url = videollamada.link_videollamada.rstrip('/') if videollamada.link_videollamada else "https://meet.gryphos.cl/test"
        logger.debug(f"URL base para prueba: {base_url}")
        
        if '?' in base_url:
            meeting_url = f"{base_url}&jwt={token}"
        else:
            meeting_url = f"{base_url}?jwt={token}"
        
        logger.debug(f"URL final de prueba construida: {meeting_url[:100]}...")
        logger.info(f"Prueba de JWT completada exitosamente para videollamada {videollamada_id} - Usuario: {request.user.username}")
        
        return JsonResponse({
            'videollamada_id': videollamada.id,
            'curso': videollamada.curso.nombre,
            'room_name': room_name,
            'jwt_token': token,
            'meeting_url': meeting_url,
            'payload': payload,
            'user': {
                'username': request.user.username,
                'full_name': request.user.get_full_name(),
                'email': request.user.email,
                'is_staff': request.user.is_staff
            }
        })
        
    except Videollamada.DoesNotExist:
        return JsonResponse({
            'error': 'Videollamada no encontrada'
        }, status=404)
    except Exception as e:
        return JsonResponse({
            'error': f'Error: {str(e)}'
        }, status=500)


@login_required
def diagnose_meeting_access(request, videollamada_id):
    """
    Función de diagnóstico para verificar problemas de acceso a videollamadas
    """
    from .models import Videollamada
    
    if not settings.DEBUG:
        return HttpResponse("Debug solo disponible en modo desarrollo", status=403)
    
    logger.info(f"Diagnóstico solicitado para videollamada {videollamada_id} - Usuario: {request.user.username}")
    
    diagnosis = {
        'user_info': {
            'username': request.user.username,
            'email': request.user.email,
            'is_staff': request.user.is_staff,
            'is_authenticated': request.user.is_authenticated,
        },
        'jwt_config': {
            'jwt_secret_configured': bool(settings.JITSI_JWT_SECRET),
            'jwt_secret_length': len(settings.JITSI_JWT_SECRET) if settings.JITSI_JWT_SECRET else 0,
        },
        'videollamada_info': {},
        'access_checks': {},
        'errors': []
    }
    
    try:
        # Verificar si la videollamada existe
        try:
            videollamada = Videollamada.objects.get(id=videollamada_id)
            diagnosis['videollamada_info'] = {
                'id': videollamada.id,
                'curso_nombre': videollamada.curso.nombre,
                'curso_id': videollamada.curso.id,
                'activa': videollamada.activa,
                'dia_semana': videollamada.get_dia_semana_display(),
                'hora_inicio': str(videollamada.hora_inicio),
                'hora_fin': str(videollamada.hora_fin),
                'tiene_enlace': bool(videollamada.link_videollamada),
                'enlace': videollamada.link_videollamada,
                'esta_activa_ahora': videollamada.esta_activa_ahora(),
            }
        except Videollamada.DoesNotExist:
            diagnosis['errors'].append(f'Videollamada {videollamada_id} no existe')
            return JsonResponse(diagnosis, status=404)
        
        # Verificar acceso al curso
        user_cursos = list(request.user.cursos.all())
        diagnosis['access_checks']['cursos_usuario'] = [{'id': c.id, 'nombre': c.nombre} for c in user_cursos]
        diagnosis['access_checks']['tiene_acceso_curso'] = videollamada.curso in user_cursos
        
        # Verificar si la videollamada está activa
        diagnosis['access_checks']['videollamada_activa'] = videollamada.activa
        
        # Verificar si está en horario
        diagnosis['access_checks']['en_horario'] = videollamada.esta_activa_ahora()
        
        # Verificar enlace
        diagnosis['access_checks']['tiene_enlace'] = bool(videollamada.link_videollamada)
        
        # Probar generación de JWT
        try:
            # Extraer el nombre de la sala de la URL de la videollamada
            from urllib.parse import urlparse
            parsed_url = urlparse(videollamada.link_videollamada)
            room_name = parsed_url.path.strip('/').split('/')[-1]
            token_response = generate_jitsi_token(request, room_name=room_name)
            diagnosis['jwt_test'] = {
                'status_code': token_response.status_code,
                'success': token_response.status_code == 200,
                'room_name': room_name,
            }
            
            if token_response.status_code == 200:
                import json
                token_data = json.loads(token_response.content)
                diagnosis['jwt_test']['token_generated'] = bool(token_data.get('token'))
                diagnosis['jwt_test']['token_length'] = len(token_data.get('token', ''))
            else:
                diagnosis['jwt_test']['error'] = token_response.content.decode()
                
        except Exception as e:
            diagnosis['jwt_test'] = {
                'error': str(e),
                'success': False
            }
        
        # Construir URL de prueba
        if videollamada.link_videollamada and diagnosis['jwt_test'].get('success'):
            try:
                base_url = videollamada.link_videollamada.rstrip('/')
                token = json.loads(token_response.content).get('token')
                if '?' in base_url:
                    meeting_url = f"{base_url}&jwt={token}"
                else:
                    meeting_url = f"{base_url}?jwt={token}"
                diagnosis['meeting_url'] = meeting_url
            except Exception as e:
                diagnosis['errors'].append(f'Error construyendo URL: {str(e)}')
        
        logger.info(f"Diagnóstico completado para videollamada {videollamada_id}")
        return JsonResponse(diagnosis)
        
    except Exception as e:
        logger.error(f"Error en diagnóstico para videollamada {videollamada_id}: {str(e)}")
        diagnosis['errors'].append(f'Error general: {str(e)}')
        return JsonResponse(diagnosis, status=500)


@login_required
def verify_jwt_token(request, videollamada_id):
    """
    Función para verificar la validez de un token JWT y su tiempo de expiración
    """
    from .models import Videollamada
    
    if not settings.DEBUG:
        return HttpResponse("Debug solo disponible en modo desarrollo", status=403)
    
    logger.info(f"Verificación de JWT solicitada para videollamada {videollamada_id} - Usuario: {request.user.username}")
    
    try:
        # Obtener la videollamada
        videollamada = Videollamada.objects.get(id=videollamada_id)
        
        # Generar un nuevo token para verificación
        # Extraer el nombre de la sala de la URL de la videollamada
        from urllib.parse import urlparse
        parsed_url = urlparse(videollamada.link_videollamada)
        room_name = parsed_url.path.strip('/').split('/')[-1]
        token_response = generate_jitsi_token(request, room_name=room_name)
        
        if token_response.status_code != 200:
            return JsonResponse({
                'error': 'Error generando token para verificación'
            }, status=500)
        
        # Extraer el token
        import json
        token_data = json.loads(token_response.content)
        token = token_data.get('token')
        
        if not token:
            return JsonResponse({
                'error': 'No se pudo obtener el token'
            }, status=500)
        
        # Decodificar el token para verificar su contenido
        try:
            logger.info(f"=== VERIFICANDO TOKEN ===")
            logger.info(f"Token a verificar: {token}")
            logger.info(f"Secret key: {settings.JITSI_JWT_SECRET}")
            decoded_token = jwt.decode(token, settings.JITSI_JWT_SECRET, algorithms=["HS256"])
            
            # Obtener tiempos
            from datetime import datetime
            import pytz
            
            now_utc = datetime.utcnow()
            exp_timestamp = decoded_token.get('exp')
            iat_timestamp = decoded_token.get('iat')  # Issued at
            
            if exp_timestamp:
                exp_utc = datetime.fromtimestamp(exp_timestamp, tz=pytz.UTC)
            else:
                exp_utc = None
                
            if iat_timestamp:
                iat_utc = datetime.fromtimestamp(iat_timestamp, tz=pytz.UTC)
            else:
                iat_utc = None
            
            # Convertir a zona horaria local
            try:
                local_tz = pytz.timezone('America/Santiago')
                now_local = now_utc.astimezone(local_tz)
                exp_local = exp_utc.astimezone(local_tz) if exp_utc else None
                iat_local = iat_utc.astimezone(local_tz) if iat_utc else None
            except:
                now_local = now_utc
                exp_local = exp_utc
                iat_local = iat_utc
            
            # Verificar si el token ha expirado
            is_expired = False
            time_until_expiry = None
            if exp_utc:
                is_expired = now_utc > exp_utc
                time_until_expiry = exp_utc - now_utc
            
            verification_result = {
                'token_valid': True,
                'token_decoded': True,
                'is_expired': is_expired,
                'times': {
                    'current_utc': str(now_utc),
                    'current_local': str(now_local),
                    'issued_at_utc': str(iat_utc) if iat_utc else None,
                    'issued_at_local': str(iat_local) if iat_local else None,
                    'expires_at_utc': str(exp_utc) if exp_utc else None,
                    'expires_at_local': str(exp_local) if exp_local else None,
                    'time_until_expiry': str(time_until_expiry) if time_until_expiry else None,
                    'time_until_expiry_seconds': time_until_expiry.total_seconds() if time_until_expiry else None,
                },
                'token_payload': {
                    'iss': decoded_token.get('iss'),
                    'aud': decoded_token.get('aud'),
                    'sub': decoded_token.get('sub'),
                    'room': decoded_token.get('room'),
                    'exp': decoded_token.get('exp'),
                    'iat': decoded_token.get('iat'),
                    'user_name': decoded_token.get('context', {}).get('user', {}).get('name'),
                    'user_email': decoded_token.get('context', {}).get('user', {}).get('email'),
                    'user_moderator': decoded_token.get('context', {}).get('user', {}).get('moderator'),
                },
                'token_length': len(token),
                'token_preview': token[:50] + "..." if len(token) > 50 else token
            }
            
            logger.info(f"=== VERIFICACIÓN JWT ===")
            logger.info(f"Token válido: {verification_result['token_valid']}")
            logger.info(f"Token expirado: {verification_result['is_expired']}")
            logger.info(f"Tiempo hasta expiración: {verification_result['times']['time_until_expiry']}")
            logger.info(f"Tiempo hasta expiración (segundos): {verification_result['times']['time_until_expiry_seconds']}")
            logger.info(f"=======================")
            
            return JsonResponse(verification_result)
            
        except jwt.ExpiredSignatureError:
            logger.error(f"Token JWT expirado para videollamada {videollamada_id}")
            return JsonResponse({
                'error': 'Token JWT expirado',
                'token_valid': False,
                'is_expired': True
            }, status=400)
            
        except jwt.InvalidTokenError as e:
            logger.error(f"Token JWT inválido para videollamada {videollamada_id}: {str(e)}")
            return JsonResponse({
                'error': f'Token JWT inválido: {str(e)}',
                'token_valid': False,
                'is_expired': False
            }, status=400)
            
    except Videollamada.DoesNotExist:
        return JsonResponse({
            'error': 'Videollamada no encontrada'
        }, status=404)
    except Exception as e:
        logger.error(f"Error verificando JWT para videollamada {videollamada_id}: {str(e)}")
        return JsonResponse({
            'error': f'Error: {str(e)}'
        }, status=500)


@login_required
def test_jwt_configurations(request, videollamada_id):
    """
    Función para probar diferentes configuraciones de JWT y encontrar la correcta
    """
    from .models import Videollamada
    
    if not settings.DEBUG:
        return HttpResponse("Debug solo disponible en modo desarrollo", status=403)
    
    logger.info(f"Prueba de configuraciones JWT solicitada para videollamada {videollamada_id} - Usuario: {request.user.username}")
    
    try:
        # Obtener la videollamada
        videollamada = Videollamada.objects.get(id=videollamada_id)
        # Extraer el nombre de la sala de la URL de la videollamada
        from urllib.parse import urlparse
        parsed_url = urlparse(videollamada.link_videollamada)
        room_name = parsed_url.path.strip('/').split('/')[-1]
        
        # Diferentes configuraciones para probar
        configurations = [
            {
                "name": "Configuración actual",
                "iss": "gryphos",
                "aud": "meet.gryphos.cl",
                "sub": "meet.gryphos.cl"
            },
            {
                "name": "Configuración con meet.gryphos.cl como audience",
                "iss": "gryphos",
                "aud": "meet.gryphos.cl",
                "sub": "meet.gryphos.cl"
            },
            {
                "name": "Configuración con dominio completo como audience",
                "iss": "gryphos",
                "aud": "https://meet.gryphos.cl",
                "sub": "meet.gryphos.cl"
            },
            {
                "name": "Configuración sin audience",
                "iss": "gryphos",
                "sub": "meet.gryphos.cl"
            },
            {
                "name": "Configuración con issuer como audience",
                "iss": "gryphos",
                "aud": "gryphos",
                "sub": "meet.gryphos.cl"
            }
        ]
        
        results = []
        
        for config in configurations:
            try:
                # Generar token con configuración específica
                payload = {
                    "iss": config["iss"],
                    "sub": config["sub"],
                    "room": room_name,
                    "exp": datetime.utcnow() + timedelta(hours=2),
                    "context": {
                        "user": {
                            "name": request.user.get_full_name() or request.user.username,
                            "email": request.user.email,
                            "avatar": "",
                            "moderator": request.user.is_staff
                        }
                    }
                }
                
                # Agregar audience solo si está definido
                if "aud" in config:
                    payload["aud"] = config["aud"]
                
                token = jwt.encode(payload, settings.JITSI_JWT_SECRET, algorithm="HS256")
                
                # Verificar el token
                try:
                    decoded_token = jwt.decode(token, settings.JITSI_JWT_SECRET, algorithms=["HS256"])
                    verification_result = {
                        "configuration": config["name"],
                        "token_valid": True,
                        "token_decoded": True,
                        "is_expired": False,
                        "payload": {
                            "iss": payload.get("iss"),
                            "aud": payload.get("aud"),
                            "sub": payload.get("sub"),
                            "room": payload.get("room"),
                            "exp": payload.get("exp")
                        },
                        "token_length": len(token),
                        "token_preview": token[:50] + "..." if len(token) > 50 else token
                    }
                except jwt.ExpiredSignatureError:
                    verification_result = {
                        "configuration": config["name"],
                        "token_valid": False,
                        "is_expired": True,
                        "error": "Token expirado"
                    }
                except jwt.InvalidTokenError as e:
                    verification_result = {
                        "configuration": config["name"],
                        "token_valid": False,
                        "is_expired": False,
                        "error": f"Token inválido: {str(e)}"
                    }
                
                results.append(verification_result)
                
            except Exception as e:
                results.append({
                    "configuration": config["name"],
                    "error": f"Error generando token: {str(e)}"
                })
        
        return JsonResponse({
            "videollamada_id": videollamada_id,
            "room_name": room_name,
            "configurations_tested": len(configurations),
            "results": results
        })
        
    except Videollamada.DoesNotExist:
        return JsonResponse({
            'error': 'Videollamada no encontrada'
        }, status=404)
    except Exception as e:
        logger.error(f"Error probando configuraciones JWT para videollamada {videollamada_id}: {str(e)}")
        return JsonResponse({
            'error': f'Error: {str(e)}'
        }, status=500)


@login_required
def comprehensive_jwt_diagnosis(request, videollamada_id):
    """
    Diagnóstico completo de JWT que analiza todos los aspectos posibles
    """
    from .models import Videollamada
    
    if not settings.DEBUG:
        return HttpResponse("Debug solo disponible en modo desarrollo", status=403)
    
    logger.info(f"Diagnóstico completo JWT solicitado para videollamada {videollamada_id} - Usuario: {request.user.username}")
    
    try:
        # Obtener la videollamada
        videollamada = Videollamada.objects.get(id=videollamada_id)
        # Extraer el nombre de la sala de la URL de la videollamada
        from urllib.parse import urlparse
        parsed_url = urlparse(videollamada.link_videollamada)
        room_name = parsed_url.path.strip('/').split('/')[-1]
        
        diagnosis = {
            "timestamp": str(datetime.utcnow()),
            "videollamada_id": videollamada_id,
            "room_name": room_name,
            "user": request.user.username,
            "sections": {}
        }
        
        # 1. Verificar configuración del servidor
        diagnosis["sections"]["server_config"] = {
            "JITSI_JWT_SECRET_configured": bool(hasattr(settings, 'JITSI_JWT_SECRET')),
            "JITSI_JWT_SECRET_length": len(settings.JITSI_JWT_SECRET) if hasattr(settings, 'JITSI_JWT_SECRET') else 0,
            "DEBUG_mode": settings.DEBUG,
            "timezone": str(settings.TIME_ZONE),
            "secret_key_configured": bool(hasattr(settings, 'SECRET_KEY')),
        }
        
        # 2. Verificar datos de la videollamada
        diagnosis["sections"]["videollamada_data"] = {
            "id": videollamada.id,
            "curso": videollamada.curso.nombre,
            "link_videollamada": videollamada.link_videollamada,
            "activa": videollamada.activa,
            "esta_activa_ahora": videollamada.esta_activa_ahora(),
            "dia_semana": videollamada.dia_semana,
            "hora_inicio": str(videollamada.hora_inicio),
            "hora_fin": str(videollamada.hora_fin),
        }
        
        # 3. Verificar acceso del usuario
        diagnosis["sections"]["user_access"] = {
            "username": request.user.username,
            "is_staff": request.user.is_staff,
            "is_superuser": request.user.is_superuser,
            "cursos_inscritos": list(request.user.cursos.values_list('nombre', flat=True)),
            "tiene_acceso_al_curso": videollamada.curso in request.user.cursos.all(),
        }
        
        # 4. Generar y analizar JWT
        try:
            # Generar token con configuración actual
            payload = {
                "iss": "gryphos",
                "aud": "meet.gryphos.cl",
                "sub": "meet.gryphos.cl",
                "room": room_name,
                "exp": datetime.utcnow() + timedelta(hours=2),
                "context": {
                    "user": {
                        "name": request.user.get_full_name() or request.user.username,
                        "email": request.user.email,
                        "avatar": "",
                        "moderator": request.user.is_staff
                    }
                }
            }
            
            token = jwt.encode(payload, settings.JITSI_JWT_SECRET, algorithm="HS256")
            
            # Decodificar para verificar
            decoded_token = jwt.decode(token, settings.JITSI_JWT_SECRET, algorithms=["HS256"])
            
            # Construir URL de prueba
            base_url = videollamada.link_videollamada.rstrip('/')
            if '?' in base_url:
                test_url = f"{base_url}&jwt={token}"
            else:
                test_url = f"{base_url}?jwt={token}"
            
            diagnosis["sections"]["jwt_analysis"] = {
                "token_generated": True,
                "token_length": len(token),
                "token_preview": token[:50] + "..." if len(token) > 50 else token,
                "payload": {
                    "iss": payload.get("iss"),
                    "aud": payload.get("aud"),
                    "sub": payload.get("sub"),
                    "room": payload.get("room"),
                    "exp": payload.get("exp"),
                    "context_user_name": payload.get("context", {}).get("user", {}).get("name"),
                    "context_user_email": payload.get("context", {}).get("user", {}).get("email"),
                    "context_user_moderator": payload.get("context", {}).get("user", {}).get("moderator"),
                },
                "decoded_token_valid": True,
                "test_url": test_url,
                "test_url_length": len(test_url),
            }
            
        except Exception as e:
            diagnosis["sections"]["jwt_analysis"] = {
                "token_generated": False,
                "error": str(e),
                "error_type": type(e).__name__
            }
        
        # 5. Probar diferentes configuraciones de audience
        audience_tests = []
        audiences_to_test = [
            "jitsi",
            "meet.gryphos.cl", 
            "https://meet.gryphos.cl",
            "gryphos",
            None  # Sin audience
        ]
        
        for aud in audiences_to_test:
            try:
                test_payload = {
                    "iss": "gryphos",
                    "sub": "meet.gryphos.cl",
                    "room": room_name,
                    "exp": datetime.utcnow() + timedelta(hours=2),
                    "context": {
                        "user": {
                            "name": request.user.get_full_name() or request.user.username,
                            "email": request.user.email,
                            "avatar": "",
                            "moderator": request.user.is_staff
                        }
                    }
                }
                
                if aud is not None:
                    test_payload["aud"] = aud
                
                test_token = jwt.encode(test_payload, settings.JITSI_JWT_SECRET, algorithm="HS256")
                
                audience_tests.append({
                    "audience": aud,
                    "token_generated": True,
                    "token_length": len(test_token),
                    "payload_aud": test_payload.get("aud")
                })
                
            except Exception as e:
                audience_tests.append({
                    "audience": aud,
                    "token_generated": False,
                    "error": str(e)
                })
        
        diagnosis["sections"]["audience_tests"] = audience_tests
        
        # 6. Verificar tiempos
        now_utc = datetime.utcnow()
        diagnosis["sections"]["timing"] = {
            "current_time_utc": str(now_utc),
            "token_expiration_utc": str(now_utc + timedelta(hours=2)),
            "time_until_expiration": "2:00:00",
            "timezone_info": "UTC"
        }
        
        logger.info(f"Diagnóstico completo JWT completado para videollamada {videollamada_id}")
        
        return JsonResponse(diagnosis, status=200)
        
    except Videollamada.DoesNotExist:
        return JsonResponse({
            'error': 'Videollamada no encontrada'
        }, status=404)
    except Exception as e:
        logger.error(f"Error en diagnóstico completo JWT para videollamada {videollamada_id}: {str(e)}")
        return JsonResponse({
            'error': f'Error: {str(e)}'
        }, status=500)