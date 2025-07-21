# Configuración de Email - Gryphos Consulting

## Situación Actual
- **Desarrollo**: Los correos se muestran en la consola del servidor
- **Producción**: Requiere configuración SMTP real

## Configuración para Producción

### Opción 1: Gmail (Recomendado)

1. **Activa la verificación en 2 pasos** en tu cuenta de Gmail
2. **Genera una contraseña de aplicación**:
   - Ve a Configuración de Google
   - Seguridad
   - Verificación en 2 pasos
   - Contraseñas de aplicación
   - Genera una nueva contraseña

3. **Configura las variables de entorno**:
```bash
EMAIL_HOST_USER=tu-email@gmail.com
EMAIL_HOST_PASSWORD=tu-contraseña-de-aplicación
```

### Opción 2: Otros proveedores

Modifica `core/settings.py`:
```python
EMAIL_HOST = 'mail.gryphos.cl'
EMAIL_PORT = 2587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'contacto@dominio.com'
EMAIL_HOST_PASSWORD = 'tu-contraseña'
```

## Seguridad

✅ **Contraseñas de aplicación**: Usa contraseñas específicas para aplicaciones  
✅ **Variables de entorno**: No hardcodees contraseñas en el código  
✅ **TLS/SSL**: Siempre usa conexiones encriptadas  
✅ **Verificación en 2 pasos**: Activa en tu cuenta de email  

## Prueba de Funcionamiento

1. Llena el formulario de contacto en `/quienes-somos/`
2. En desarrollo: Revisa la consola del servidor
3. En producción: Revisa la bandeja de entrada de `contacto@gryphos.cl` 