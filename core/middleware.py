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
