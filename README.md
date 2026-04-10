# Gryphos CL

Plataforma web de gestión educativa y consultoría empresarial construida con Django.

## Características Principales

- **Gestión de Cursos y Capacitaciones**: Creación de cursos, inscripción de estudiantes, seguimiento de pagos
- **Plataforma de Aprendizaje**: Dashboard personalizado, foros de discusión, entregas y calificaciones
- **Sistema de Evaluaciones**: Evaluaciones con rúbricas dinámicas, exportación a Excel
- **Sistema de Tickets**: Gestión de soporte técnico con clasificación y prioridades
- **Blog**: Publicación de noticias, tutoriales y casos de éxito
- **Integración con Jitsi Meet**: Videollamadas programadas por curso
- **Autenticación**: Login con email/username, recuperación de contraseña, activación por email

## Requisitos

- Python 3.9+
- PostgreSQL 12+
- Docker y Docker Compose (opcional)
- Nginx (para producción)

## Instalación Local

```bash
# Clonar repositorio
git clone <repo-url>
cd gryphos_cl

# Crear entorno virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Instalar dependencias
pip install -r requirements.txt

# Configurar variables de entorno
cp .env.example .env
# Editar .env con tu configuración

# Ejecutar migraciones
python manage.py migrate

# Crear superusuario
python manage.py createsuperuser

# Iniciar servidor de desarrollo
python manage.py runserver
```

## Configuración

### Variables de Entorno

Configura tu archivo `.env`:

```env
SECRET_KEY=<tu-secret-key>
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1
EMAIL_HOST=smtp.tuserver.com
EMAIL_PORT=587
EMAIL_HOST_USER=user@tuserver.com
EMAIL_HOST_PASSWORD=password
DEFAULT_FROM_EMAIL=Gryphos <noreply@gryphos.cl>
DB_ENGINE=django.db.backends.postgresql
DB_USERNAME=postgres
DB_PASS=mypassword
DB_HOST=localhost
DB_PORT=5432
DB_NAME=gryphos
```

## Docker

```bash
# Construir e iniciar contenedores
docker-compose up -d

# Ver logs
docker-compose logs -f
```

## Deployment en Producción

### Usando Docker

```bash
docker-compose -f docker-compose.yml up -d --build
```

### Script de Despliegue

```bash
./deploy_production.sh
```

### Render.com

El proyecto incluye configuración para despliegue en Render.com (`render.yaml`).

## Estructura del Proyecto

```
gryphos_cl/
├── core/                 # Configuración principal de Django
├── home/                 # App principal
│   ├── models.py         # Modelos de datos
│   ├── views.py          # Vistas y lógica de negocio
│   ├── forms.py          # Formularios
│   ├── urls.py           # Rutas
│   ├── admin.py          # Configuración admin
│   ├── service/          # Módulos de servicio
│   └── templates/        # Templates HTML
├── static/               # Archivos estáticos
├── media/                # Archivos subidos
├── nginx/                # Configuración Nginx
├── requirements.txt      # Dependencias Python
├── Dockerfile           # Imagen Docker
└── docker-compose.yml   # Orquestación Docker
```

## Modelos Principales

- **CustomUser**: Usuarios del sistema
- **Curso**: Cursos y capacitaciones
- **Evaluacion**: Evaluaciones con ponderación
- **Rubrica**: Rúbricas de evaluación
- **Entrega**: Entregas de estudiantes
- **Post/Comment**: Foros de discusión
- **BlogPost**: Artículos del blog
- **TicketSoporte**: Tickets de soporte

## Integraciones

- **PostgreSQL**: Base de datos principal
- **Mailcow**: Gestión de cuentas de email
- **Jitsi Meet**: Videollamadas con tokens JWT
- **Nginx**: Proxy reverso y servir estáticos
- **Gunicorn**: Servidor WSGI

## Comandos Útiles

```bash
# Migraciones
python manage.py makemigrations
python manage.py migrate

# Recolectar estáticos
python manage.py collectstatic

# Crear superusuario
python manage.py createsuperuser

# Shell de Django
python manage.py shell

# Tests
python manage.py test
```

## Documentación Adicional

- [Solución Error 500](SOLUCION_ERROR_500.md)
- [Configuración de Email](EMAIL_CONFIG.md)
- [Sistema de Rúbricas](SOLUCION_RUBRICA_DINAMICA.md)

## Licencia

Propiedad de Gryphos.
