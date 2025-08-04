import re
from django.http import HttpResponseBadRequest
from django.conf import settings
import logging

logger = logging.getLogger('home.middleware')

class FixHostHeaderMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Debug: Mostrar headers originales
        if settings.DEBUG:
            logger.info("\n=== HEADERS ORIGINALES ===")
            for header, value in request.META.items():
                if header.startswith('HTTP_') or header in ('REMOTE_ADDR', 'SERVER_NAME'):
                    logger.info(f"{header}: {value}")

        # Corregir header Host malformado
        host = request.META.get('HTTP_HOST', '')
        if ',' in host:
            if settings.DEBUG:
                logger.info(f"Host header contiene comas: {host}")

            # Tomar el primer host válido
            clean_host = host.split(',')[0].strip()
            request.META['HTTP_HOST'] = clean_host
            request.META['SERVER_NAME'] = clean_host

            if settings.DEBUG:
                logger.info(f"Host header corregido: {clean_host}")

        # Validación adicional de host
        allowed_hosts = settings.ALLOWED_HOSTS
        if settings.DEBUG:
            allowed_hosts += ['*']  # Permite cualquier host en DEBUG

        response = self.get_response(request)
        return response


class SessionDebugMiddleware:
    """
    Middleware para debuggear problemas de sesión
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Solo mostrar debug si DEBUG está activo y hay problemas de sesión
        if settings.DEBUG and not request.user.is_authenticated and hasattr(request, 'session'):
            logger.info(f"\n=== DEBUG SESIÓN ===")
            logger.info(f"Usuario: {request.user}")
            logger.info(f"Session ID: {request.session.session_key}")
        
        response = self.get_response(request)
        return response


class SessionFixMiddleware:
    """
    Middleware para forzar la creación de sesiones y mejorar la persistencia
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Forzar creación de sesión si no existe
        if not request.session.session_key:
            request.session.create()
            if settings.DEBUG:
                logger.info(f"=== SESIÓN CREADA ===")
                logger.info(f"Nueva session key: {request.session.session_key}")
        
        response = self.get_response(request)
        
        # Forzar guardado de sesión
        if request.session.modified:
            request.session.save()
            if settings.DEBUG:
                logger.info(f"=== SESIÓN GUARDADA ===")
                logger.info(f"Session key: {request.session.session_key}")
        
        return response


class NoCacheMiddleware:
    """
    Middleware para prevenir el caché de páginas dinámicas
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        
        # Agregar headers para prevenir caché en páginas dinámicas
        if not request.path.startswith('/static/') and not request.path.startswith('/media/'):
            response['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
            response['Pragma'] = 'no-cache'
            response['Expires'] = '0'
        
        return response
