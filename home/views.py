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
import re
import logging
import traceback
from datetime import datetime

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
    
    # Renderizar el template HTML
    html_message = render_to_string('emails/instrucciones_pago.html', {
        'nombre_interesado': inscripcion.nombre_interesado,
        'nombre_empresa': inscripcion.nombre_empresa,
        'curso_nombre': curso_nombre,
        'fecha_solicitud': fecha_solicitud,
        'correo_contacto': inscripcion.correo_contacto,
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
        return True
    except Exception as e:
        print(f"Error enviando correo de instrucciones de pago: {e}")
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
        return True
    except Exception as e:
        print(f"Error enviando correo de bienvenida: {e}")
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
        print(f"Error enviando correo de inscripción: {e}")
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
                    
                    messages.success(request, '¡Inscripción enviada exitosamente! Revisa tu correo para las instrucciones de pago.')
                    return redirect('inscripcion-curso')
                else:
                    # Si falla el envío del correo, eliminar la inscripción
                    inscripcion.delete()
                    messages.error(request, 'Hubo un error al enviar las instrucciones de pago. Por favor, intenta nuevamente.')
                    
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
                if enviar_correo_bienvenida(request, user, password_temp, inscripcion.curso.nombre):
                    messages.success(request, f'Inscripción marcada como pagada. Usuario creado: {user.username}')
                else:
                    messages.warning(request, f'Usuario creado pero error al enviar correo de bienvenida. Usuario: {user.username}, Contraseña: {password_temp}')
                
                return JsonResponse({
                    'success': True, 
                    'message': 'Inscripción marcada como pagada',
                    'username': user.username,
                    'password_temp': password_temp
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