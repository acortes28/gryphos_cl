#!/bin/bash

# Script para verificar estado del servidor - Gryphos CL
# Uso: ./check_server_status.sh

echo "Verificando estado del servidor Gryphos CL..."
echo "================================================"

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Función para verificar servicio
check_service() {
    local service=$1
    local name=$2
    
    if sudo systemctl is-active --quiet $service; then
        echo -e "${GREEN}$name: ACTIVO${NC}"
    else
        echo -e "${RED}$name: INACTIVO${NC}"
    fi
}

# Verificar servicios
echo "Estado de Servicios:"
check_service "nginx" "Nginx"
check_service "gunicorn" "Gunicorn"

echo ""
echo "Verificando conectividad:"

# Verificar sitio web
if curl -s -o /dev/null -w "%{http_code}" https://gryphos.cl | grep -q "200\|301\|302"; then
    echo -e "${GREEN}Sitio web: ACCESIBLE${NC}"
else
    echo -e "${RED}Sitio web: NO ACCESIBLE${NC}"
fi

# Verificar socket de Gunicorn
SOCKET_FILE="/home/acortes/repositorio/gryphos_cl/gryphos.sock"
if [ -S "$SOCKET_FILE" ]; then
    echo -e "${GREEN}Socket Gunicorn: EXISTE${NC}"
else
    echo -e "${RED}Socket Gunicorn: NO EXISTE${NC}"
fi

echo ""
echo "Logs Recientes:"
echo "------------------"

# Mostrar últimos logs de Gunicorn
echo "Gunicorn (últimas 5 líneas):"
sudo journalctl -u gunicorn --no-pager -n 5

echo ""
echo "Nginx (últimas 5 líneas):"
sudo tail -n 5 /var/log/nginx/error.log 2>/dev/null || echo "No se encontraron logs de Nginx"

echo ""
echo "Verificando archivos críticos:"

# Verificar archivos importantes
PROJECT_DIR="/home/acortes/repositorio/gryphos_cl"
FILES=(
    "manage.py"
    "core/settings.py"
    "core/settings_production.py"
    "gunicorn_production.py"
    "requirements.txt"
)

for file in "${FILES[@]}"; do
    if [ -f "$PROJECT_DIR/$file" ]; then
        echo -e "${GREEN}$file${NC}"
    else
        echo -e "${RED}$file${NC}"
    fi
done

echo ""
echo "Verificando directorios:"

# Verificar directorios importantes
DIRS=(
    "logs"
    "media"
    "staticfiles"
    "env"
)

for dir in "${DIRS[@]}"; do
    if [ -d "$PROJECT_DIR/$dir" ]; then
        echo -e "${GREEN}$dir${NC}"
    else
        echo -e "${RED}$dir${NC}"
    fi
done

echo ""
echo "Comandos útiles:"
echo "-------------------"
echo "Ver estado completo: sudo systemctl status gunicorn nginx"
echo "Ver logs en tiempo real: sudo journalctl -u gunicorn -f"
echo "Reiniciar Gunicorn: sudo systemctl restart gunicorn"
echo "Recargar Nginx: sudo systemctl reload nginx"
echo "Verificar puertos: sudo netstat -tlnp | grep :80"
echo "Verificar SSL: sudo certbot certificates"

echo ""
echo "================================================"
echo "Verificación completada" 