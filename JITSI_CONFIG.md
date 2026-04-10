# Configuración de Jitsi Meet - Gryphos CL

## Descripción General

Gryphos integra **Jitsi Meet** para videoconferencias. Los usuarios pueden unirse a reuniones programadas con autenticación segura mediante tokens JWT.

### Características

- Videollamadas con autenticación JWT
- Reuniones programadas asociadas a cursos
- Control de acceso por horario
- Roles de moderador para usuarios staff
- Integración con el modelo `Reunion`

---

## Configuración

### Variables de Entorno

Configura en tu archivo `.env`:

```env
JITSI_JWT_SECRET=tu_secret_key_segura
```

### Generar Secret Key

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## Modelo de Datos

### Reunion

```
Reunion
├── nombre: str
├── organizador: ForeignKey(CustomUser)
├── participantes: ManyToMany(CustomUser)
├── fecha_reunion: Date
├── hora_inicio: Time
├── hora_fin: Time
├── link_videollamada: URL
├── descripcion: str (opcional)
├── activa: bool
├── fecha_creacion: DateTime
└── fecha_modificacion: DateTime
```

### Métodos del Modelo

- `esta_activa_ahora()`: Verifica si la reunión está dentro del horario (permite unirse 5 min antes)
- `puede_unirse(usuario)`: Verifica si el usuario es organizador o participante

---

## Generación de Tokens JWT

### Flujo

1. Usuario solicita unirse a una reunión
2. Sistema verifica autenticación y permisos
3. Se genera token JWT con los datos del usuario
4. Usuario es redirigido a Jitsi con el token

### Payload del Token

```json
{
  "iss": "gryphos",
  "aud": "jitsi",
  "sub": "meet.gryphos.cl",
  "room": "nombre_sala",
  "exp": "timestamp + 2 horas",
  "context": {
    "user": {
      "name": "Nombre Completo",
      "email": "email@ejemplo.com",
      "avatar": "url_avatar",
      "moderator": true
    }
  }
}
```

### Parámetros del Token

| Campo | Descripción |
|-------|-------------|
| `iss` | Emisor del token (identificador de Gryphos) |
| `aud` | Audiencia ("jitsi") |
| `sub` | Dominio del servidor Jitsi |
| `room` | Nombre de la sala |
| `exp` | Tiempo de expiración (2 horas) |
| `context.user.name` | Nombre del usuario |
| `context.user.moderator` | true si es staff/admin |

---

## Configuración del Servidor Jitsi

### Instalación de Jitsi Meet

```bash
# Agregar repositorio
curl https://download.jitsi.org/jitsi-signing-key.pub | apt-key add -
echo "deb https://download.jitsi.org stable/" > /etc/apt/sources.list.d/jitsi-stable.list

# Instalar
apt update
apt install jitsi-meet -y
```

### Configuración de JWT

Edita `/etc/jitsi/meet/meet.gryphos.cl-config.js`:

```javascript
// Habilitar autenticación JWT
const config = {
    // ...
};

// Autenticación
config.authentication = "token";
config.tokenAuthUrl = "/external_api/";

config.testing = {
    noSSL: false
};
```

Edita `/etc/jitsi/prosody/prosody.cfg.lua`:

```
-- Habilitar autenticación JWT
VirtualHost "meet.gryphos.cl"
    authentication = "token"
    
    app_id = "gryphos"
    app_secret = "tu_secret_key_segura"
    
    allow_empty_token = false
```

### Parámetros de Seguridad

| Parámetro | Valor Recomendado |
|-----------|-------------------|
| `app_id` | Identificador de la aplicación |
| `app_secret` | Secret key (mínimo 32 caracteres) |
| `allow_empty_token` | false |
| `lifetime` | 7200 (2 horas en segundos) |

---

## Endpoints de la API

### Generar Token

```
POST /jitsi/generate-token/
```

**Parámetros:**
- `room_name`: Nombre de la sala (opcional)

**Respuesta:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### Unirse a Reunión

```
GET /reuniones/<reunion_id>/unirse/
```

Redirige a Jitsi con token JWT si:
- El usuario está autenticado
- Es organizador o participante
- La reunión está dentro del horario activo

---

## Uso

### Crear una Reunión

1. Ve a **Reuniones** en el menú
2. Clic en **Crear Reunión**
3. Completa:
   - Nombre de la reunión
   - Fecha y horario
   - Participantes
   - Enlace de videollamada (Jitsi room)
4. Guarda

### Unirse a una Reunión

1. Ve a **Reuniones**
2. Selecciona una reunión activa
3. Clic en **Unirse**
4. El sistema genera automáticamente el token JWT
5. Serás redirigido a Jitsi Meet

### Verificar Horario Activo

El sistema permite unirse:
- 5 minutos antes del horario de inicio
- Hasta la hora de fin

---

## Permisos y Roles

| Tipo de Usuario | Rol en Jitsi | Capacidad |
|-----------------|--------------|-----------|
| Staff/Admin | Moderador | Control total de la sala |
| Usuario normal | Participante | Unirse, hablar, compartir |

---

## Troubleshooting

| Problema | Solución |
|----------|----------|
| Token no válido | Verifica que `JITSI_JWT_SECRET` coincida en Gryphos y Jitsi |
| No puedo unirme | Verifica que la reunión esté activa (horario y estado) |
| Usuario no permitido | Confirma que eres organizador o participante |
| Error 403 | Token JWT inválido o expirado |
| Sala no existe | Verifica que el link de videollamada sea correcto |

### Verificar Logs

```bash
# Logs de Jitsi
tail -f /var/log/jitsi/jvb.log

# Logs de Prosody
tail -f /var/log/prosody/prosody.log
```

---

## Integración con Cursos

Las reuniones pueden asociarse a cursos para:
- Clases en vivo
- Sesiones de revisión
- Tutorías grupales

Los estudiantes inscritos pueden ver las reuniones programadas en la sección del curso.

---

## Consideraciones de Seguridad

- Los tokens expiran en 2 horas
- Solo usuarios autenticados pueden generar tokens
- Los usuarios staff tienen rol de moderador
- Las reuniones verifican pertenencia antes de generar token
