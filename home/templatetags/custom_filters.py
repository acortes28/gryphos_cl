from django import template

register = template.Library()

@register.filter
def get_item(dictionary, key):
    """Filtro para acceder a elementos de un diccionario en templates"""
    return dictionary.get(key)

@register.filter
def debug_videollamada(videollamada):
    """Filtro para debug de videollamadas"""
    try:
        return f"Activa: {videollamada.activa}, Enlace: {bool(videollamada.link_videollamada)}, Esta_activa_ahora: {videollamada.esta_activa_ahora()}"
    except Exception as e:
        return f"Error: {str(e)}"

@register.filter
def get_field(form, field_name):
    """Filtro para obtener un campo específico del formulario"""
    if not field_name or field_name == '':
        return None
    try:
        return form[field_name]
    except KeyError:
        return None

@register.filter
def get_criterio_field(form, criterio_id):
    """Filtro específico para obtener campos de criterio de rúbrica"""
    field_name = f'criterio_{criterio_id}'
    try:
        return form[field_name]
    except KeyError:
        return None

@register.filter
def puntaje_entero(value):
    """Filtro para mostrar puntajes como enteros sin decimales"""
    try:
        if value is None:
            return 0
        # Convertir a float y luego a int para eliminar decimales
        return int(float(value))
    except (ValueError, TypeError):
        return 0 