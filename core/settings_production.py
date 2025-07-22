"""
Configuración específica para producción de Gryphos CL
"""

import os
from pathlib import Path
from .settings import *

# Configuración específica para producción
DEBUG = False

# Configuración de logging mejorada para producción
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'ERROR',
            'class': 'logging.FileHandler',
            'filename': '/home/acortes/repositorio/gryphos_cl/logs/django_error.log',
            'formatter': 'verbose',
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
        'gunicorn': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/home/acortes/repositorio/gryphos_cl/logs/gunicorn.log',
            'maxBytes': 1024 * 1024 * 5,  # 5 MB
            'backupCount': 5,
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file', 'console'],
            'level': 'ERROR',
            'propagate': True,
        },
        'home.views': {
            'handlers': ['file', 'console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'gunicorn.error': {
            'level': 'INFO',
            'handlers': ['gunicorn'],
            'propagate': False,
        },
        'gunicorn.access': {
            'level': 'INFO',
            'handlers': ['gunicorn'],
            'propagate': False,
        },
    },
}

# Configuración de archivos estáticos optimizada
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Configuración de sesiones para HTTPS
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'

# Configuración de seguridad adicional
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

# Configuración de CSRF para HTTPS
CSRF_TRUSTED_ORIGINS = [
    'https://gryphos.cl',
    'https://www.gryphos.cl',
]

# Configuración de archivos de medios
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# Configuración de caché (opcional, para mejorar rendimiento)
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake',
    }
}

# Configuración de base de datos optimizada para producción
DATABASES['default']['CONN_MAX_AGE'] = 600  # 10 minutos
DATABASES['default']['OPTIONS'] = {
    'options': '-c search_path=public -c timezone=America/Santiago'
}

# Configuración de email para producción
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'mail.gryphos.cl'
EMAIL_PORT = 2587
EMAIL_USE_TLS = True
EMAIL_USE_SSL = False
EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER', 'contacto@gryphos.cl')
EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD')
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER
SERVER_EMAIL = EMAIL_HOST_USER

# Configuración de middleware adicional para producción
MIDDLEWARE.insert(0, 'django.middleware.security.SecurityMiddleware')

# Configuración de templates optimizada
TEMPLATES[0]['OPTIONS']['debug'] = False

# Configuración de archivos estáticos adicional
STATICFILES_FINDERS = [
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
]

# Configuración de WhiteNoise optimizada
WHITENOISE_USE_FINDERS = False
WHITENOISE_AUTOREFRESH = False
WHITENOISE_MANIFEST_STRICT = False

# Configuración de manejo de errores personalizado
ADMINS = [
    ('Admin', 'admin@gryphos.cl'),
]

# Configuración de manejo de errores 500
HANDLER404 = 'home.views.custom_404'
HANDLER500 = 'home.views.custom_500'

# Configuración de timeouts
DATA_UPLOAD_MAX_MEMORY_SIZE = 10485760  # 10MB
FILE_UPLOAD_MAX_MEMORY_SIZE = 10485760  # 10MB

# Configuración de sesiones mejorada
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_AGE = 86400  # 24 horas
SESSION_SAVE_EVERY_REQUEST = False
SESSION_EXPIRE_AT_BROWSER_CLOSE = False 