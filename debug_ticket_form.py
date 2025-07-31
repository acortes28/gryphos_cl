#!/usr/bin/env python
"""
Script de debug para el formulario de tickets de soporte
"""
import os
import sys
import django

# Configurar Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

from django.test import RequestFactory
from django.contrib.auth import get_user_model
from home.forms import TicketSoporteForm
from home.models import ClasificacionTicket, SubclasificacionTicket, Curso

User = get_user_model()

def debug_ticket_form():
    """
    Función para debuggear el formulario de tickets
    """
    print("=== DEBUG TICKET FORM ===")
    
    # 1. Verificar que las clasificaciones existen
    print("\n1. Verificando clasificaciones en la base de datos:")
    clasificaciones = ClasificacionTicket.objects.filter(activa=True)
    print(f"Clasificaciones activas encontradas: {clasificaciones.count()}")
    for c in clasificaciones:
        print(f"  - {c.nombre} (ID: {c.id})")
        subclasificaciones = c.subclasificaciones.filter(activa=True)
        print(f"    Subclasificaciones: {subclasificaciones.count()}")
        for sub in subclasificaciones:
            print(f"      - {sub.nombre}")
    
    # 2. Crear un request simulado
    factory = RequestFactory()
    request = factory.post('/fake-url/', {
        'titulo': 'Test Ticket Debug',
        'descripcion': 'Este es un ticket de prueba para debug',
        'clasificacion': 'Problemas Técnicos',
        'subclasificacion': 'Acceso a la plataforma'
    })
    
    print(f"\n2. Datos del request simulado:")
    print(f"  - titulo: {request.POST.get('titulo')}")
    print(f"  - descripcion: {request.POST.get('descripcion')}")
    print(f"  - clasificacion: {request.POST.get('clasificacion')}")
    print(f"  - subclasificacion: {request.POST.get('subclasificacion')}")
    
    # 3. Crear el formulario
    print("\n3. Creando formulario...")
    form = TicketSoporteForm(request.POST)
    
    print(f"Formulario creado: {form}")
    print(f"Campos del formulario: {list(form.fields.keys())}")
    
    # 4. Verificar las opciones iniciales
    print("\n4. Opciones iniciales del formulario:")
    print(f"Clasificación choices: {len(form.fields['clasificacion'].choices)}")
    for choice in form.fields['clasificacion'].choices:
        print(f"  - {choice[1]} (valor: {choice[0]})")
    
    print(f"Subclasificación widget choices: {len(form.fields['subclasificacion'].widget.choices)}")
    for choice in form.fields['subclasificacion'].widget.choices:
        print(f"  - {choice[1]} (valor: {choice[0]})")
    
    # 5. Validar el formulario
    print("\n5. Validando formulario...")
    is_valid = form.is_valid()
    print(f"Formulario válido: {is_valid}")
    
    if not is_valid:
        print("Errores del formulario:")
        for field, errors in form.errors.items():
            print(f"  - {field}: {errors}")
    
    # 6. Verificar datos limpios
    if is_valid:
        print("\n6. Datos limpios:")
        for field, value in form.cleaned_data.items():
            print(f"  - {field}: {value}")
    
    # 7. Probar guardado
    if is_valid:
        print("\n7. Probando guardado...")
        try:
            # Crear un usuario de prueba
            user, created = User.objects.get_or_create(
                username='debug_user',
                defaults={'email': 'debug@test.com'}
            )
            
            # Obtener un curso de prueba
            curso = Curso.objects.first()
            if not curso:
                print("  ✗ No hay cursos disponibles para la prueba")
                return
            
            ticket = form.save(commit=False)
            ticket.usuario = user
            ticket.curso = curso
            ticket.save()
            
            print(f"  ✓ Ticket guardado exitosamente (ID: {ticket.id})")
            print(f"    - Clasificación: {ticket.clasificacion}")
            print(f"    - Subclasificación: {ticket.subclasificacion}")
            
            # Limpiar el ticket de prueba
            ticket.delete()
            print("  ✓ Ticket de prueba eliminado")
            
        except Exception as e:
            print(f"  ✗ Error al guardar: {e}")
    
    print("\n=== FIN DEBUG TICKET FORM ===")

def test_subclasificaciones_ajax():
    """
    Simular la función AJAX de subclasificaciones
    """
    print("\n=== TEST SUBCLASIFICACIONES AJAX ===")
    
    clasificacion_nombre = 'Problemas Técnicos'
    print(f"Probando con clasificación: {clasificacion_nombre}")
    
    try:
        clasificacion_obj = ClasificacionTicket.objects.get(nombre=clasificacion_nombre, activa=True)
        print(f"✓ Clasificación encontrada: {clasificacion_obj.nombre}")
        
        subclasificaciones = clasificacion_obj.subclasificaciones.filter(activa=True)
        print(f"Subclasificaciones encontradas: {subclasificaciones.count()}")
        
        choices = [('', 'Selecciona una subclasificación')] + [
            (sub.nombre, sub.nombre) for sub in subclasificaciones
        ]
        
        print("Choices generados:")
        for choice in choices:
            print(f"  - {choice[1]} (valor: {choice[0]})")
            
    except ClasificacionTicket.DoesNotExist:
        print(f"✗ Clasificación '{clasificacion_nombre}' no encontrada")
    
    print("=== FIN TEST SUBCLASIFICACIONES AJAX ===")

if __name__ == '__main__':
    debug_ticket_form()
    test_subclasificaciones_ajax() 