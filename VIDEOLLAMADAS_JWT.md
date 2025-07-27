# Videollamadas con JWT - Gryphos Consulting

## Descripción

Se ha implementado un sistema de videollamadas seguro que utiliza tokens JWT para autenticar a los usuarios antes de permitirles unirse a las videollamadas de sus cursos.

## Funcionalidades

### 1. Función `join_meeting`

La función principal `join_meeting` se encarga de:

- **Verificación de acceso**: Comprueba que el usuario esté inscrito en el curso de la videollamada
- **Validación de estado**: Verifica que la videollamada esté activa y en horario
- **Generación de JWT**: Utiliza la función `generate_jitsi_token` para crear un token JWT específico
- **Redirección segura**: Redirige al usuario a la videollamada con el token JWT

### 2. Función `generate_jitsi_token` (Refactorizada)

La función `generate_jitsi_token` ha sido refactorizada para:

- **Aceptar parámetros opcionales**: `room_name` y `user`
- **Generar tokens específicos**: Para salas específicas o acceso general
- **Mantener compatibilidad**: Con el uso existente sin parámetros
- **Reutilización**: Ser utilizada por otras funciones como `join_meeting`

### 3. Estructura del JWT

El token JWT incluye:

```json
{
  "iss": "gryphos",
  "aud": "jitsi", 
  "sub": "meet.gryphos.cl",
  "room": "curso_{curso_id}_{videollamada_id}",
  "exp": "timestamp_expiración",
  "context": {
    "user": {
      "name": "Nombre del usuario",
      "email": "email@usuario.com",
      "avatar": "URL_avatar",
      "moderator": true/false
    }
  }
}
```

### 4. URLs implementadas

- `/join-meeting/<videollamada_id>/` - Función principal para unirse a videollamadas
- `/test-meeting-jwt/<videollamada_id>/` - Función de prueba para verificar JWT (solo en DEBUG)
- `/jitsi/generate-token/` - Función para generar tokens JWT (refactorizada)

## Configuración requerida

### Variables de entorno

```bash
JITSI_JWT_SECRET=tu_clave_secreta_jwt_aqui
```

### Configuración de Jitsi

Asegúrate de que tu servidor Jitsi esté configurado para:

1. **Aceptar JWT**: Habilitar autenticación JWT
2. **Configurar issuer**: El issuer debe ser "gryphos"
3. **Configurar audience**: El audience debe ser "jitsi"
4. **Configurar dominio**: El dominio debe ser "meet.gryphos.cl"

## Uso en el portal del cliente

### Antes (enlaces directos)
```html
<a href="{{ videollamada.link_videollamada }}" target="_blank">
  Ir a la videollamada
</a>
```

### Después (con JWT)
```html
<a href="{% url 'join_meeting' videollamada.id %}" target="_blank">
  Ir a la videollamada
</a>
```

## Flujo de funcionamiento

1. **Usuario hace clic** en "Unirse ahora" en el portal del cliente
2. **Sistema verifica** que el usuario tenga acceso al curso
3. **Sistema verifica** que la videollamada esté activa
4. **Sistema llama** a `generate_jitsi_token` con el nombre de sala específico
5. **Sistema construye** la URL con el token JWT generado
6. **Usuario es redirigido** a la videollamada con autenticación automática

## Arquitectura del código

### Principio DRY (Don't Repeat Yourself)

- **Función centralizada**: `generate_jitsi_token` maneja toda la lógica de generación de JWT
- **Reutilización**: `join_meeting` y `test_meeting_jwt` utilizan la función centralizada
- **Mantenibilidad**: Cambios en la lógica JWT solo requieren modificar una función
- **Consistencia**: Todos los tokens JWT se generan con la misma lógica

## Seguridad

### Verificaciones implementadas

- ✅ Usuario autenticado
- ✅ Usuario inscrito en el curso
- ✅ Videollamada activa
- ✅ Videollamada en horario
- ✅ Enlace configurado
- ✅ Token JWT con expiración (2 horas)

### Logs de seguridad

El sistema registra información detallada en diferentes niveles:

#### Nivel INFO (Información importante)
- Inicio de generación de JWT
- JWT generado exitosamente
- Intentos de unirse a videollamadas
- Accesos exitosos a videollamadas
- Pruebas de JWT completadas

#### Nivel DEBUG (Información detallada)
- Verificación de acceso a cursos
- Estado de videollamadas
- Verificación de enlaces
- Generación de payload JWT
- Construcción de URLs
- Extracción de tokens

#### Nivel WARNING (Advertencias)
- Intentos de acceso sin autenticación
- Acceso denegado a videollamadas
- Videollamadas no activas
- Intentos de acceso a funciones de debug en producción

#### Nivel ERROR (Errores)
- Errores de generación de JWT
- Errores de extracción de tokens
- Videollamadas sin enlace configurado
- Errores internos del servidor
- Errores de acceso a base de datos

## Pruebas

### Función de prueba

En modo DEBUG, puedes usar:
```
/test-meeting-jwt/<videollamada_id>/
```

Esta función devuelve un JSON con:
- Token JWT generado
- URL de la videollamada
- Información del payload
- Datos del usuario

### Ejemplo de respuesta

```json
{
  "videollamada_id": 1,
  "curso": "Curso de Python",
  "room_name": "curso_1_1",
  "jwt_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "meeting_url": "https://meet.gryphos.cl/curso_1_1?jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "payload": {...},
  "user": {...}
}
```

## Mantenimiento

### Monitoreo

- **Logs de acceso**: Revisar logs de acceso a videollamadas en nivel INFO
- **Logs de errores**: Monitorear logs de nivel ERROR para problemas de JWT
- **Logs de seguridad**: Revisar logs de nivel WARNING para intentos de acceso no autorizados
- **Logs de debug**: Usar logs de nivel DEBUG para troubleshooting detallado

### Comandos útiles para monitoreo

```bash
# Ver logs de videollamadas
grep "videollamada" /path/to/logs/django.log

# Ver logs de JWT
grep "JWT" /path/to/logs/django.log

# Ver errores de acceso
grep "ERROR.*join_meeting" /path/to/logs/django.log

# Ver accesos exitosos
grep "INFO.*se unió exitosamente" /path/to/logs/django.log

# Ver intentos de acceso no autorizados
grep "WARNING.*Acceso denegado" /path/to/logs/django.log
```

### Actualizaciones

- Mantener actualizada la clave JWT_SECRET
- Revisar la configuración de Jitsi periódicamente
- Actualizar la expiración de tokens según necesidades

## Troubleshooting

### Problemas comunes

1. **Error "No tienes acceso"**: Usuario no inscrito en el curso
2. **Error "Videollamada no activa"**: Fuera de horario o inactiva
3. **Error "Sin enlace"**: Videollamada sin URL configurada
4. **Error JWT**: Problema con la clave secreta o configuración

### Soluciones

1. Verificar inscripción del usuario en el curso
2. Revisar horarios y estado de la videollamada
3. Configurar enlace en la videollamada
4. Verificar variable de entorno JITSI_JWT_SECRET 