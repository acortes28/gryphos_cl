# Solución para Error 500 en Producción - Gryphos CL

## Problema Identificado

El error 500 al intentar publicar posts en el servidor de producción se debe principalmente a:

1. **Configuración de DEBUG hardcodeada** como `False` sin logging detallado
2. **Configuración incorrecta de cookies seguras** para HTTPS
3. **Falta de manejo de errores personalizado**
4. **Configuración subóptima de Gunicorn**
5. **Posibles problemas con archivos estáticos**

## Archivos Creados/Modificados

### 1. Script de Diagnóstico (`debug_production.py`)
- Verifica configuración de Django
- Comprueba conexión a base de datos
- Valida archivos estáticos
- Prueba formularios y modelos
- Verifica instalación de bleach

### 2. Configuración de Producción (`core/settings_production.py`)
- Logging detallado para producción
- Configuración correcta de cookies para HTTPS
- Optimización de archivos estáticos
- Configuración de seguridad mejorada

### 3. Vistas de Error Personalizadas (`home/views.py`)
- `custom_404()` - Manejo de errores 404
- `custom_500()` - Manejo de errores 500

### 4. Plantillas de Error
- `home/templates/pages/404.html` - Página de error 404
- `home/templates/pages/500.html` - Página de error 500

### 5. Script de Despliegue (`deploy_production.sh`)
- Automatiza todo el proceso de despliegue
- Verifica dependencias
- Configura Gunicorn correctamente
- Crea servicio systemd

## Instrucciones de Despliegue

### Paso 1: Preparar el Servidor

```bash
# Conectarse al servidor
ssh acortes@149.50.141.70

# Navegar al directorio del proyecto
cd /home/acortes/repositorio/gryphos_cl

# Crear directorios necesarios
mkdir -p logs media
```

### Paso 2: Ejecutar Diagnóstico

```bash
# Ejecutar script de diagnóstico
python debug_production.py

# Revisar el log generado
cat debug_production.log
```

### Paso 3: Desplegar con el Script Automatizado

```bash
# Ejecutar script de despliegue
./deploy_production.sh
```

### Paso 4: Verificar el Despliegue

```bash
# Verificar estado de Gunicorn
sudo systemctl status gunicorn

# Verificar logs en tiempo real
sudo journalctl -u gunicorn -f

# Verificar conectividad
curl -I https://gryphos.cl
```

## Configuración Manual (Alternativa)

Si prefieres configurar manualmente:

### 1. Configurar Gunicorn

```bash
# Crear configuración de Gunicorn
cat > gunicorn_production.py << 'EOF'
import multiprocessing

bind = "unix:/home/acortes/repositorio/gryphos_cl/gryphos.sock"
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "sync"
timeout = 30
accesslog = "/home/acortes/repositorio/gryphos_cl/logs/gunicorn_access.log"
errorlog = "/home/acortes/repositorio/gryphos_cl/logs/gunicorn_error.log"
loglevel = "info"
preload_app = True
raw_env = ["DJANGO_SETTINGS_MODULE=core.settings_production"]
EOF
```

### 2. Crear Servicio Systemd

```bash
sudo tee /etc/systemd/system/gunicorn.service > /dev/null << 'EOF'
[Unit]
Description=Gunicorn daemon for Gryphos CL
After=network.target

[Service]
Type=notify
User=acortes
Group=acortes
WorkingDirectory=/home/acortes/repositorio/gryphos_cl
Environment="PATH=/home/acortes/repositorio/gryphos_cl/env/bin"
Environment="DJANGO_SETTINGS_MODULE=core.settings_production"
ExecStart=/home/acortes/repositorio/gryphos_cl/env/bin/gunicorn --config gunicorn_production.py core.wsgi:application
ExecReload=/bin/kill -s HUP $MAINPID
KillMode=mixed
TimeoutStopSec=5
PrivateTmp=true
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
```

### 3. Activar Servicio

```bash
sudo systemctl daemon-reload
sudo systemctl enable gunicorn
sudo systemctl start gunicorn
```

## Verificación y Monitoreo

### Comandos Útiles

```bash
# Ver estado de servicios
sudo systemctl status gunicorn nginx

# Ver logs de Gunicorn
sudo journalctl -u gunicorn -f

# Ver logs de Nginx
sudo tail -f /var/log/nginx/error.log

# Ver logs de Django
tail -f /home/acortes/repositorio/gryphos_cl/logs/django_error.log

# Reiniciar servicios
sudo systemctl restart gunicorn
sudo systemctl reload nginx
```

### Verificar Funcionalidad

1. **Acceder al sitio**: https://gryphos.cl
2. **Probar login**: Verificar que las sesiones funcionen
3. **Crear post**: Intentar publicar un post en el foro
4. **Crear artículo**: Intentar publicar un artículo en el blog
5. **Verificar archivos**: Comprobar que las imágenes se suban correctamente

## Solución de Problemas Comunes

### Error: "ModuleNotFoundError: No module named 'bleach'"
```bash
pip install bleach==6.2.0
```

### Error: "Permission denied" en socket
```bash
sudo chown acortes:acortes /home/acortes/repositorio/gryphos_cl/gryphos.sock
sudo chmod 660 /home/acortes/repositorio/gryphos_cl/gryphos.sock
```

### Error: "Static files not found"
```bash
python manage.py collectstatic --noinput --clear
```

### Error: "Database connection failed"
```bash
# Verificar variables de entorno
echo $DB_ENGINE $DB_NAME $DB_USERNAME

# Verificar conexión manual
python manage.py dbshell
```

### Error: "CSRF verification failed"
- Verificar `CSRF_TRUSTED_ORIGINS` en settings
- Asegurar que el dominio esté incluido

## Configuración de Variables de Entorno

Crear archivo `.env` en el directorio del proyecto:

```bash
# Base de datos
DB_ENGINE=django.db.backends.postgresql
DB_NAME=tu_base_de_datos
DB_USERNAME=tu_usuario
DB_PASS=tu_password
DB_HOST=localhost
DB_PORT=5432

# Django
SECRET_KEY=tu_secret_key_muy_segura
DEBUG=False

# Email
EMAIL_HOST_USER=contacto@gryphos.cl
EMAIL_HOST_PASSWORD=tu_password_email
```

## Notas Importantes

1. **Backup**: Siempre hacer backup antes de desplegar
2. **Logs**: Revisar logs regularmente para detectar problemas
3. **Permisos**: Asegurar que los permisos de archivos sean correctos
4. **SSL**: Verificar que el certificado SSL esté vigente
5. **Monitoreo**: Configurar alertas para errores críticos

## Contacto

Si persisten los problemas, revisar:
- Logs de Gunicorn: `sudo journalctl -u gunicorn`
- Logs de Nginx: `/var/log/nginx/error.log`
- Logs de Django: `/home/acortes/repositorio/gryphos_cl/logs/django_error.log` 