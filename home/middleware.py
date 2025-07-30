from django.contrib import messages
from django.shortcuts import redirect
from django.contrib.auth import logout
import time
import logging
import traceback

logger = logging.getLogger('home.middleware')

class SessionTimeoutMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        logger.info("SessionTimeoutMiddleware inicializado")

    def __call__(self, request):
        logger.debug(f"SessionTimeoutMiddleware procesando request: {request.path}")
        logger.debug(f"Método HTTP: {request.method}")
        logger.debug(f"Usuario autenticado: {request.user.is_authenticated}")
        logger.debug(f"Usuario: {request.user}")
        logger.debug(f"Tiene sesión: {hasattr(request, 'session')}")
        
        if hasattr(request, 'session'):
            logger.debug(f"Session key: {request.session.session_key}")
            logger.debug(f"Session exists: {request.session.session_key is not None}")
            logger.debug(f"Session data keys: {list(request.session.keys())}")
        
        # Solo procesar si el usuario está autenticado y tiene sesión
        if (request.user.is_authenticated and 
            hasattr(request, 'session') and 
            request.session.session_key):
            
            logger.debug(f"Usuario autenticado: {request.user.username}")
            
            try:
                # Obtener el tiempo de la última actividad
                last_activity = request.session.get('last_activity')
                current_time = time.time()
                
                logger.debug(f"Última actividad: {last_activity}, Tiempo actual: {current_time}")
                
                if last_activity:
                    # Calcular el tiempo transcurrido desde la última actividad
                    time_elapsed = current_time - last_activity
                    logger.debug(f"Tiempo transcurrido: {time_elapsed} segundos")
                    
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
                logger.debug(f"Actividad actualizada para usuario {request.user.username}")
                
            except Exception as e:
                logger.error(f"Error en SessionTimeoutMiddleware: {str(e)}")
                logger.error(f"Traceback completo: {traceback.format_exc()}")
                # Si hay algún error, simplemente continuar sin interrumpir
                pass
        else:
            logger.debug("Usuario no autenticado o sin sesión")
        
        try:
            logger.debug("Llamando a get_response...")
            response = self.get_response(request)
            logger.debug(f"Response obtenida: {type(response)}")
            logger.debug(f"SessionTimeoutMiddleware completado para: {request.path}")
            return response
        except Exception as e:
            logger.error(f"Error al obtener response: {str(e)}")
            logger.error(f"Traceback completo: {traceback.format_exc()}")
            raise 