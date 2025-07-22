#!/usr/bin/env python3
"""
Script de diagnóstico para problemas de producción en Gryphos CL
"""

import os
import sys
import django
from pathlib import Path

# Configurar Django
BASE_DIR = Path(__file__).resolve().parent
sys.path.append(str(BASE_DIR))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')

# Configurar logging para capturar errores
import logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s %(name)s %(message)s',
    handlers=[
        logging.FileHandler('debug_production.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

def check_django_setup():
    """Verificar que Django esté configurado correctamente"""
    try:
        django.setup()
        logger.info("✅ Django configurado correctamente")
        return True
    except Exception as e:
        logger.error(f"❌ Error configurando Django: {e}")
        return False

def check_database():
    """Verificar conexión a la base de datos"""
    try:
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            logger.info("✅ Conexión a base de datos exitosa")
        return True
    except Exception as e:
        logger.error(f"❌ Error de conexión a base de datos: {e}")
        return False

def check_static_files():
    """Verificar configuración de archivos estáticos"""
    try:
        from django.conf import settings
        from django.contrib.staticfiles.finders import find
        
        # Verificar que STATIC_ROOT existe
        static_root = Path(settings.STATIC_ROOT)
        if not static_root.exists():
            logger.warning(f"⚠️ STATIC_ROOT no existe: {static_root}")
        else:
            logger.info(f"✅ STATIC_ROOT existe: {static_root}")
        
        # Verificar archivos estáticos
        static_file = find('css/material-kit.css')
        if static_file:
            logger.info(f"✅ Archivo estático encontrado: {static_file}")
        else:
            logger.warning("⚠️ No se encontró material-kit.css")
        
        return True
    except Exception as e:
        logger.error(f"❌ Error verificando archivos estáticos: {e}")
        return False

def check_models():
    """Verificar que los modelos estén disponibles"""
    try:
        from home.models import Post, BlogPost, CustomUser
        
        # Verificar que los modelos se pueden importar
        logger.info("✅ Modelos importados correctamente")
        
        # Verificar que las tablas existen
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name IN ('home_post', 'home_blogpost', 'home_customuser')
            """)
            tables = [row[0] for row in cursor.fetchall()]
            logger.info(f"✅ Tablas encontradas: {tables}")
        
        return True
    except Exception as e:
        logger.error(f"❌ Error verificando modelos: {e}")
        return False

def check_forms():
    """Verificar que los formularios funcionen"""
    try:
        from home.forms import PostForm, BlogPostForm
        from home.models import Curso
        
        # Verificar PostForm
        form_data = {
            'title': 'Test Post',
            'content': '<p>Test content</p>',
            'category': 'general'
        }
        
        # Verificar si hay cursos disponibles
        cursos = Curso.objects.all()
        if cursos.exists():
            form_data['curso'] = cursos.first().id
        
        form = PostForm(data=form_data)
        if form.is_valid():
            logger.info("✅ PostForm válido")
        else:
            logger.warning(f"⚠️ PostForm inválido: {form.errors}")
        
        # Verificar BlogPostForm
        blog_form_data = {
            'title': 'Test Blog Post',
            'content': '<p>Test blog content</p>',
            'category': 'noticias'
        }
        
        form = BlogPostForm(data=blog_form_data)
        if form.is_valid():
            logger.info("✅ BlogPostForm válido")
        else:
            logger.warning(f"⚠️ BlogPostForm inválido: {form.errors}")
        
        return True
    except Exception as e:
        logger.error(f"❌ Error verificando formularios: {e}")
        return False

def check_bleach():
    """Verificar que bleach esté disponible"""
    try:
        import bleach
        logger.info(f"✅ Bleach disponible: {bleach.__version__}")
        
        # Probar limpieza de HTML
        test_html = '<p>Test <script>alert("xss")</script> content</p>'
        cleaned = bleach.clean(test_html, tags=['p'], strip=True)
        logger.info(f"✅ Bleach funciona: {cleaned}")
        
        return True
    except ImportError:
        logger.error("❌ Bleach no está instalado")
        return False
    except Exception as e:
        logger.error(f"❌ Error con bleach: {e}")
        return False

def check_settings():
    """Verificar configuración crítica"""
    try:
        from django.conf import settings
        
        logger.info(f"DEBUG: {settings.DEBUG}")
        logger.info(f"ALLOWED_HOSTS: {settings.ALLOWED_HOSTS}")
        logger.info(f"CSRF_TRUSTED_ORIGINS: {settings.CSRF_TRUSTED_ORIGINS}")
        logger.info(f"STATIC_ROOT: {settings.STATIC_ROOT}")
        logger.info(f"STATICFILES_STORAGE: {settings.STATICFILES_STORAGE}")
        
        return True
    except Exception as e:
        logger.error(f"❌ Error verificando configuración: {e}")
        return False

def main():
    """Ejecutar todas las verificaciones"""
    logger.info("🔍 Iniciando diagnóstico de producción...")
    
    checks = [
        ("Django Setup", check_django_setup),
        ("Database", check_database),
        ("Static Files", check_static_files),
        ("Models", check_models),
        ("Forms", check_forms),
        ("Bleach", check_bleach),
        ("Settings", check_settings),
    ]
    
    results = []
    for name, check_func in checks:
        logger.info(f"\n--- Verificando {name} ---")
        try:
            result = check_func()
            results.append((name, result))
        except Exception as e:
            logger.error(f"❌ Error en verificación {name}: {e}")
            results.append((name, False))
    
    # Resumen
    logger.info("\n" + "="*50)
    logger.info("📊 RESUMEN DE DIAGNÓSTICO")
    logger.info("="*50)
    
    for name, result in results:
        status = "✅ PASÓ" if result else "❌ FALLÓ"
        logger.info(f"{name}: {status}")
    
    failed = [name for name, result in results if not result]
    if failed:
        logger.error(f"\n❌ Verificaciones fallidas: {', '.join(failed)}")
        logger.info("\n💡 RECOMENDACIONES:")
        logger.info("1. Revisar logs de Gunicorn: journalctl -u gunicorn")
        logger.info("2. Verificar permisos de archivos")
        logger.info("3. Revisar configuración de base de datos")
        logger.info("4. Ejecutar: python manage.py collectstatic")
    else:
        logger.info("\n✅ Todas las verificaciones pasaron")
    
    logger.info(f"\n📝 Log completo guardado en: debug_production.log")

if __name__ == "__main__":
    main() 