# Configuración de Email - Gryphos Consulting

## Mailcow

Gryphos utiliza **Mailcow** como plataforma de correo electrónico. Mailcow es una solución autohospedada que proporciona:
- Servidor SMTP/IMAP/POP3
- Webmail (SOGo)
- Gestión de dominios y cuentas de email
- API para automatización

## Configuración SMTP

### Variables de Entorno

Configura en tu archivo `.env`:

```env
EMAIL_HOST=mail.tuserver.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=usuario@gryphos.cl
EMAIL_HOST_PASSWORD=tu_contraseña
DEFAULT_FROM_EMAIL=Gryphos <noreply@gryphos.cl>
```

### Valores Típicos

| Parámetro | Valor |
|-----------|-------|
| HOST | mail.tuserver.com |
| PORT | 587 (TLS) o 465 (SSL) |
| USAR_TLS | True |
| USAR_SSL | False (si usas puerto 587) |

## API de Mailcow

Gryphos puede crear cuentas de email automáticamente a través de la API de Mailcow.

### Configuración API

```env
MAILCOW_API_URL=https://mail.tuserver.com/api/v1
MAILCOW_API_KEY=tu_api_key
```

### Obtener API Key

1. Accede a Mailcow como administrador
2. Ve a **Administración** > **Configuración de API**
3. Genera una nueva clave API
4. Asegúrate de habilitar los endpoints necesarios

### Endpoints Utilizados

- `POST /api/v1/add/mailbox` - Crear cuenta de email
- `DELETE /api/v1/delete/mailbox` - Eliminar cuenta
- `GET /api/v1/get/mailbox/all` - Listar cuentas

## Cuentas de Email del Sistema

Gryphos crea automáticamente cuentas de email para usuarios cuando:
- Se inscriben en un curso pagado
- El administrador lo solicita

Formato de email: `nombre.apellido@gryphos.cl`

## Prueba de Funcionamiento

1. **Desarrollo**: Los correos se muestran en la consola del servidor
2. **Producción**: Envía un email de prueba desde la plataforma
3. **Verificar**: Revisa la bandeja en SOGo o tu cliente de email

### Script de Prueba

```python
from django.core.mail import send_mail

send_mail(
    subject='Prueba de configuración',
    message='Este es un email de prueba.',
    from_email='noreply@gryphos.cl',
    recipient_list=['test@gryphos.cl'],
    fail_silently=False,
)
```

## Seguridad

- Usa conexiones TLS para enviar correos
- Almacena las credenciales en variables de entorno, nunca en el código
- La API key de Mailcow debe tener permisos limitados
- Revisa regularmente los logs de Mailcow para detectar anomalías

## Troubleshooting

| Problema | Solución |
|----------|----------|
| Connection refused | Verifica que Mailcow esté corriendo y el puerto sea correcto |
| Authentication failed | Confirma usuario y contraseña |
| TLS handshake failed | Verifica que `EMAIL_USE_TLS=True` |
| Emails no llegan | Revisa carpeta de spam y logs de Mailcow |
