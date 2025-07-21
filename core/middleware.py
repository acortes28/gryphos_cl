import re
from django.http import HttpResponseBadRequest
from django.conf import settings

class FixHostHeaderMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Debug: Mostrar headers originales
        if settings.DEBUG:
            print("\n=== HEADERS ORIGINALES ===")
            for header, value in request.META.items():
                if header.startswith('HTTP_') or header in ('REMOTE_ADDR', 'SERVER_NAME'):
                    print(f"{header}: {value}")

        # Corregir header Host malformado
        host = request.META.get('HTTP_HOST', '')
        if ',' in host:
            if settings.DEBUG:
                print(f"Host header contiene comas: {host}")

            # Tomar el primer host válido
            clean_host = host.split(',')[0].strip()
            request.META['HTTP_HOST'] = clean_host
            request.META['SERVER_NAME'] = clean_host

            if settings.DEBUG:
                print(f"Host header corregido: {clean_host}")

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
        if settings.DEBUG:
            print(f"\n=== DEBUG SESIÓN ===")
            print(f"Usuario autenticado: {request.user.is_authenticated}")
            print(f"Usuario: {request.user}")
            print(f"Session ID: {request.session.session_key}")
            print(f"Session data: {dict(request.session)}")
            print(f"Cookies: {request.COOKIES}")
        
        response = self.get_response(request)
        
        if settings.DEBUG:
            print(f"Response status: {response.status_code}")
            if hasattr(response, 'cookies'):
                print(f"Response cookies: {dict(response.cookies)}")
        
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
                print(f"=== SESIÓN CREADA ===")
                print(f"Nueva session key: {request.session.session_key}")
        
        response = self.get_response(request)
        
        # Forzar guardado de sesión
        if request.session.modified:
            request.session.save()
            if settings.DEBUG:
                print(f"=== SESIÓN GUARDADA ===")
                print(f"Session key: {request.session.session_key}")
        
        return response
