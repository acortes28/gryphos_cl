#!/bin/bash

# Script de despliegue para producción - Gryphos CL
# Uso: ./deploy_production.sh

set -e  # Salir si hay algún error

echo "Iniciando despliegue de producción..."

# Variables
PROJECT_DIR="/home/acortes/repositorio/gryphos_cl"
LOGS_DIR="$PROJECT_DIR/logs"
MEDIA_DIR="$PROJECT_DIR/media"
STATIC_DIR="$PROJECT_DIR/staticfiles"

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Función para logging
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

# Verificar que estamos en el directorio correcto
if [ ! -f "manage.py" ]; then
    error "No se encontró manage.py. Asegúrate de estar en el directorio del proyecto."
    exit 1
fi

# Crear directorios necesarios
log "Creando directorios necesarios..."
mkdir -p "$LOGS_DIR"
mkdir -p "$MEDIA_DIR"
mkdir -p "$STATIC_DIR"

# Verificar permisos
log "Verificando permisos..."
chmod 755 "$LOGS_DIR"
chmod 755 "$MEDIA_DIR"
chmod 755 "$STATIC_DIR"

# Activar entorno virtual (si existe)
if [ -d "env" ]; then
    log "Activando entorno virtual..."
    source env/bin/activate
fi

# Instalar/actualizar dependencias
log "Instalando dependencias..."
pip install -r requirements.txt

# Verificar que bleach esté instalado
if ! python -c "import bleach" 2>/dev/null; then
    error "Bleach no está instalado. Instalando..."
    pip install bleach==6.2.0
fi

# Ejecutar migraciones
log "Ejecutando migraciones..."
python manage.py migrate --noinput

# Recolectar archivos estáticos
log "Recolectando archivos estáticos..."
python manage.py collectstatic --noinput --clear

# Verificar configuración de Django
log "Verificando configuración de Django..."
python manage.py check --deploy

# Ejecutar diagnóstico personalizado
log "Ejecutando diagnóstico..."
python debug_production.py

# Verificar que el socket de Gunicorn existe
SOCKET_FILE="$PROJECT_DIR/gryphos.sock"
if [ -S "$SOCKET_FILE" ]; then
    log "Deteniendo Gunicorn anterior..."
    sudo systemctl stop gunicorn || true
    sleep 2
fi

# Crear archivo de configuración de Gunicorn mejorado
log "Creando configuración de Gunicorn..."
cat > gunicorn_production.py << EOF
# Configuración de Gunicorn para producción
import multiprocessing
import os

# Configuración básica
bind = "unix:$SOCKET_FILE"
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "sync"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50

# Configuración de logging
accesslog = "$LOGS_DIR/gunicorn_access.log"
errorlog = "$LOGS_DIR/gunicorn_error.log"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Configuración de timeouts
timeout = 30
keepalive = 2
graceful_timeout = 30

# Configuración de seguridad
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# Configuración de procesos
preload_app = True
daemon = False

# Configuración de archivos
pidfile = "$PROJECT_DIR/gunicorn.pid"
user = "acortes"
group = "acortes"

# Configuración de entorno
raw_env = [
    "DJANGO_SETTINGS_MODULE=core.settings_production",
]

def when_ready(server):
    server.log.info("Gunicorn está listo para recibir conexiones")

def worker_int(worker):
    worker.log.info("Worker recibió INT o QUIT")

def pre_fork(server, worker):
    server.log.info("Worker spawned (pid: %s)", worker.pid)

def post_fork(server, worker):
    server.log.info("Worker spawned (pid: %s)", worker.pid)

def post_worker_init(worker):
    worker.log.info("Worker initialized (pid: %s)", worker.pid)

def worker_abort(worker):
    worker.log.info("Worker aborted (pid: %s)", worker.pid)
EOF

# Crear archivo de servicio systemd
log "Creando servicio systemd..."
sudo tee /etc/systemd/system/gunicorn.service > /dev/null << EOF
[Unit]
Description=Gunicorn daemon for Gryphos CL
After=network.target

[Service]
Type=notify
User=acortes
Group=acortes
WorkingDirectory=$PROJECT_DIR
Environment="PATH=$PROJECT_DIR/env/bin"
Environment="DJANGO_SETTINGS_MODULE=core.settings_production"
ExecStart=$PROJECT_DIR/env/bin/gunicorn --config gunicorn_production.py core.wsgi:application
ExecReload=/bin/kill -s HUP \$MAINPID
KillMode=mixed
TimeoutStopSec=5
PrivateTmp=true
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Recargar systemd y habilitar servicio
log "Configurando servicio systemd..."
sudo systemctl daemon-reload
sudo systemctl enable gunicorn

# Iniciar Gunicorn
log "Iniciando Gunicorn..."
sudo systemctl start gunicorn

# Verificar estado del servicio
sleep 3
if sudo systemctl is-active --quiet gunicorn; then
    log "Gunicorn iniciado correctamente"
else
    error "Error iniciando Gunicorn"
    sudo systemctl status gunicorn
    exit 1
fi

# Verificar que el socket existe
if [ -S "$SOCKET_FILE" ]; then
    log "Socket de Gunicorn creado correctamente"
else
    error "Socket de Gunicorn no encontrado"
    exit 1
fi

# Verificar permisos del socket
sudo chown acortes:acortes "$SOCKET_FILE"
sudo chmod 660 "$SOCKET_FILE"

# Recargar Nginx
log "Recargando Nginx..."
sudo systemctl reload nginx

# Verificar estado de Nginx
if sudo systemctl is-active --quiet nginx; then
    log "Nginx funcionando correctamente"
else
    error "Error con Nginx"
    sudo systemctl status nginx
    exit 1
fi

# Verificar conectividad
log "Verificando conectividad..."
if curl -s -o /dev/null -w "%{http_code}" https://gryphos.cl | grep -q "200\|301\|302"; then
    log "Sitio web accesible"
else
    warn "No se pudo verificar la conectividad del sitio web"
fi

# Mostrar logs recientes
log "Mostrando logs recientes de Gunicorn..."
sudo journalctl -u gunicorn --no-pager -n 10

log "Despliegue completado exitosamente!"
log "Para ver logs en tiempo real: sudo journalctl -u gunicorn -f"
log "Para reiniciar: sudo systemctl restart gunicorn"
log "Para verificar estado: sudo systemctl status gunicorn" 