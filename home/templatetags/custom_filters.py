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