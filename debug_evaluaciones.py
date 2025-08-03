#!/usr/bin/env python
import os
import sys
import django

# Configurar Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

from home.models import Curso, Evaluacion
from django.contrib.auth import get_user_model

User = get_user_model()

def debug_evaluaciones():
    print("=== DEBUG EVALUACIONES ===")
    
    # Verificar cursos
    cursos = Curso.objects.all()
    print(f"Cursos encontrados: {cursos.count()}")
    for curso in cursos:
        print(f"  - Curso: {curso.nombre} (ID: {curso.id}, Activo: {curso.activo})")
        
        # Verificar evaluaciones del curso
        evaluaciones = Evaluacion.objects.filter(curso=curso)
        print(f"    Evaluaciones: {evaluaciones.count()}")
        for eval in evaluaciones:
            print(f"      - Evaluación: {eval.nombre} (ID: {eval.id}, Activa: {eval.activa})")
    
    # Verificar usuarios staff
    staff_users = User.objects.filter(is_staff=True)
    print(f"\nUsuarios staff: {staff_users.count()}")
    for user in staff_users:
        print(f"  - {user.username} ({user.email})")
    
    # Verificar evaluaciones totales
    total_evaluaciones = Evaluacion.objects.all()
    print(f"\nTotal evaluaciones en BD: {total_evaluaciones.count()}")
    for eval in total_evaluaciones:
        print(f"  - {eval.nombre} (Curso: {eval.curso.nombre}, Activa: {eval.activa})")

if __name__ == '__main__':
    debug_evaluaciones() 