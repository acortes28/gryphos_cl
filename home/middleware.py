from django.utils import timezone
from django.contrib import messages
from django.shortcuts import redirect
from django.contrib.auth import logout
from django.urls import reverse
import time

class SessionTimeoutMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            # Obtener el tiempo de la última actividad
            last_activity = request.session.get('last_activity')
            current_time = time.time()
            
            if last_activity:
                # Calcular el tiempo transcurrido desde la última actividad
                time_elapsed = current_time - last_activity
                
                # Si han pasado más de 50 minutos, mostrar advertencia
                if time_elapsed > 3000:  # 50 minutos (3000 segundos)
                    messages.warning(
                        request, 
                        'Tu sesión expirará en 10 minutos por inactividad. '
                        'Realiza alguna acción para mantenerla activa.'
                    )
                
                # Si han pasado más de 1 hora, cerrar sesión
                if time_elapsed > 3600:  # 1 hora (3600 segundos)
                    logout(request)
                    messages.error(
                        request, 
                        'Tu sesión ha expirado por inactividad. '
                        'Por favor, inicia sesión nuevamente.'
                    )
                    return redirect('login')
            
            # Actualizar el tiempo de última actividad
            request.session['last_activity'] = current_time
        
        response = self.get_response(request)
        return response 