from django.contrib import messages
from django.shortcuts import redirect
from django.contrib.auth import logout
import time
import logging
import traceback

logger = logging.getLogger('home.middleware')

class MessageCleanupMiddleware:
    """
    Middleware para limpiar automáticamente los mensajes después de mostrarlos
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        
        # Limpiar mensajes después de procesar la respuesta
        if hasattr(request, '_messages'):
            storage = messages.get_messages(request)
            storage.used = True  # Marcar todos los mensajes como usados
        
        return response

class SessionTimeoutMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        logger.info("SessionTimeoutMiddleware inicializado")

    def __call__(self, request):
        # Solo procesar si el usuario está autenticado y tiene sesión
        if (request.user.is_authenticated and 
            hasattr(request, 'session') and 
            request.session.session_key):
            
            try:
                # Obtener el tiempo de la última actividad
                last_activity = request.session.get('last_activity')
                current_time = time.time()
                
                if last_activity:
                    # Calcular el tiempo transcurrido desde la última actividad
                    time_elapsed = current_time - last_activity
                    
                    # Si han pasado más de 1 hora, cerrar sesión
                    if time_elapsed > 3600:  # 1 hora (3600 segundos)
                        logger.warning(f"Sesión expirada para usuario {request.user.username}")
                        logout(request)
                        messages.error(
                            request, 
                            'Tu sesión ha expirado por inactividad. '
                            'Por favor, inicia sesión nuevamente.'
                        )
                        return redirect('/')
                
                # Actualizar el tiempo de última actividad
                request.session['last_activity'] = current_time
                request.session.modified = True
                
            except Exception as e:
                logger.error(f"Error en SessionTimeoutMiddleware: {str(e)}")
                logger.error(f"Traceback completo: {traceback.format_exc()}")
                # Si hay algún error, simplemente continuar sin interrumpir
                pass
        
        try:
            response = self.get_response(request)
            return response
        except Exception as e:
            logger.error(f"Error al obtener response: {str(e)}")
            logger.error(f"Traceback completo: {traceback.format_exc()}")
            raise 