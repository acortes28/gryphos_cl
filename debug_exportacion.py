#!/usr/bin/env python3
"""
Script de debug para la funcionalidad de exportación de calificaciones
Analiza qué datos se están obteniendo y cómo se están procesando
"""

import os
import sys
import django
from datetime import datetime

# Configurar Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

from django.db import connection
from home.models import Curso, Calificacion, Evaluacion, Rubrica, CriterioRubrica, Esperable, ResultadoRubrica, PuntajeCriterio, CustomUser

def debug_exportacion(curso_id):
    """
    Función de debug para analizar la exportación de calificaciones
    """
    print("=" * 80)
    print("DEBUG EXPORTACIÓN DE CALIFICACIONES")
    print("=" * 80)
    
    try:
        # 1. Verificar que el curso existe
        curso = Curso.objects.get(id=curso_id)
        print(f"✅ Curso encontrado: {curso.nombre} (ID: {curso.id})")
        
        # 2. Obtener todas las calificaciones del curso
        calificaciones = Calificacion.objects.filter(
            evaluacion__curso=curso
        ).select_related(
            'estudiante', 
            'evaluacion', 
            'calificado_por'
        ).prefetch_related(
            'evaluacion__rubrica__criterios__esperables'
        ).order_by('estudiante__first_name', 'estudiante__last_name', 'evaluacion__fecha_inicio')
        
        print(f"✅ Total de calificaciones encontradas: {calificaciones.count()}")
        
        # 3. Analizar cada calificación
        for i, calificacion in enumerate(calificaciones, 1):
            print(f"\n--- CALIFICACIÓN {i} ---")
            print(f"Estudiante: {calificacion.estudiante.get_full_name()} ({calificacion.estudiante.email})")
            print(f"Evaluación: {calificacion.evaluacion.nombre} (ID: {calificacion.evaluacion.id})")
            print(f"Nota: {calificacion.nota}")
            print(f"Calificado por: {calificacion.calificado_por.get_full_name()}")
            
            # 4. Verificar si la evaluación tiene rúbrica
            evaluacion = calificacion.evaluacion
            if hasattr(evaluacion, 'rubrica') and evaluacion.rubrica:
                rubrica = evaluacion.rubrica
                print(f"✅ Evaluación tiene rúbrica: {rubrica.nombre}")
                print(f"   Objetivo: {rubrica.objetivo}")
                print(f"   Aprendizaje esperado: {rubrica.aprendizaje_esperado}")
                
                # 5. Analizar criterios de la rúbrica
                criterios = rubrica.criterios.all()
                print(f"   Total de criterios: {criterios.count()}")
                
                for j, criterio in enumerate(criterios, 1):
                    print(f"   Criterio {j}: {criterio.nombre}")
                    print(f"     Objetivo: {criterio.objetivo}")
                    print(f"     Puntaje máximo: {criterio.puntaje}")
                    
                    # 6. Analizar esperables del criterio
                    esperables = criterio.esperables.all()
                    print(f"     Total de esperables: {esperables.count()}")
                    
                    for k, esperable in enumerate(esperables, 1):
                        print(f"       Esperable {k}: {esperable.nivel} - {esperable.puntaje} pts")
                        print(f"         Descripción: {esperable.descripcion}")
                
                # 7. Verificar si existe ResultadoRubrica para este estudiante
                try:
                    resultado_rubrica = ResultadoRubrica.objects.get(
                        rubrica=rubrica,
                        estudiante=calificacion.estudiante
                    )
                    print(f"✅ ResultadoRubrica encontrado para el estudiante")
                    print(f"   Evaluador: {resultado_rubrica.evaluador.get_full_name()}")
                    print(f"   Fecha evaluación: {resultado_rubrica.fecha_evaluacion}")
                    print(f"   Puntaje total: {resultado_rubrica.puntaje_total}")
                    print(f"   Nota final: {resultado_rubrica.nota_final}")
                    
                    # 8. Analizar puntajes de criterios
                    puntajes_criterios = resultado_rubrica.puntajes_criterios.all()
                    print(f"   Total de puntajes de criterios: {puntajes_criterios.count()}")
                    
                    for puntaje_criterio in puntajes_criterios:
                        print(f"     Criterio: {puntaje_criterio.criterio.nombre}")
                        print(f"       Puntaje obtenido: {puntaje_criterio.puntaje_obtenido}")
                        if puntaje_criterio.esperable_seleccionado:
                            print(f"       Esperable seleccionado: {puntaje_criterio.esperable_seleccionado.nivel}")
                        else:
                            print(f"       Esperable seleccionado: Ninguno")
                        print(f"       Comentarios: {puntaje_criterio.comentarios}")
                        
                except ResultadoRubrica.DoesNotExist:
                    print(f"❌ NO se encontró ResultadoRubrica para el estudiante")
                    print(f"   Esto significa que la evaluación no fue calificada con rúbrica")
                    
            else:
                print(f"❌ La evaluación NO tiene rúbrica asociada")
        
        # 9. Estadísticas generales
        print(f"\n" + "=" * 80)
        print("ESTADÍSTICAS GENERALES")
        print("=" * 80)
        
        evaluaciones_con_rubrica = 0
        evaluaciones_sin_rubrica = 0
        resultados_rubrica_encontrados = 0
        resultados_rubrica_faltantes = 0
        
        for calificacion in calificaciones:
            evaluacion = calificacion.evaluacion
            if hasattr(evaluacion, 'rubrica') and evaluacion.rubrica:
                evaluaciones_con_rubrica += 1
                try:
                    ResultadoRubrica.objects.get(
                        rubrica=evaluacion.rubrica,
                        estudiante=calificacion.estudiante
                    )
                    resultados_rubrica_encontrados += 1
                except ResultadoRubrica.DoesNotExist:
                    resultados_rubrica_faltantes += 1
            else:
                evaluaciones_sin_rubrica += 1
        
        print(f"Total de calificaciones: {calificaciones.count()}")
        print(f"Evaluaciones con rúbrica: {evaluaciones_con_rubrica}")
        print(f"Evaluaciones sin rúbrica: {evaluaciones_sin_rubrica}")
        print(f"ResultadosRubrica encontrados: {resultados_rubrica_encontrados}")
        print(f"ResultadosRubrica faltantes: {resultados_rubrica_faltantes}")
        
        # 10. Verificar consultas SQL ejecutadas
        print(f"\n" + "=" * 80)
        print("CONSULTAS SQL EJECUTADAS")
        print("=" * 80)
        
        for query in connection.queries:
            print(f"Query: {query['sql']}")
            print(f"Tiempo: {query['time']}s")
            print("-" * 40)
        
        print(f"Total de consultas: {len(connection.queries)}")
        
    except Curso.DoesNotExist:
        print(f"❌ ERROR: No se encontró el curso con ID {curso_id}")
    except Exception as e:
        print(f"❌ ERROR: {str(e)}")
        import traceback
        traceback.print_exc()

def debug_exportacion_simple(curso_id):
    """
    Versión simplificada del debug para verificar datos básicos
    """
    print("=" * 80)
    print("DEBUG SIMPLIFICADO - EXPORTACIÓN")
    print("=" * 80)
    
    try:
        curso = Curso.objects.get(id=curso_id)
        print(f"Curso: {curso.nombre}")
        
        # Obtener calificaciones
        calificaciones = Calificacion.objects.filter(evaluacion__curso=curso)
        print(f"Calificaciones: {calificaciones.count()}")
        
        # Verificar rúbricas
        rubricas = Rubrica.objects.filter(evaluacion__curso=curso)
        print(f"Rúbricas: {rubricas.count()}")
        
        # Verificar criterios
        criterios = CriterioRubrica.objects.filter(rubrica__evaluacion__curso=curso)
        print(f"Criterios: {criterios.count()}")
        
        # Verificar esperables
        esperables = Esperable.objects.filter(criterio__rubrica__evaluacion__curso=curso)
        print(f"Esperables: {esperables.count()}")
        
        # Verificar resultados de rúbrica
        resultados = ResultadoRubrica.objects.filter(rubrica__evaluacion__curso=curso)
        print(f"ResultadosRubrica: {resultados.count()}")
        
        # Verificar puntajes de criterios
        puntajes = PuntajeCriterio.objects.filter(resultado_rubrica__rubrica__evaluacion__curso=curso)
        print(f"PuntajeCriterio: {puntajes.count()}")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python debug_exportacion.py <curso_id>")
        sys.exit(1)
    
    curso_id = int(sys.argv[1])
    
    print("Ejecutando debug completo...")
    debug_exportacion(curso_id)
    
    print("\n" + "=" * 80)
    print("Ejecutando debug simplificado...")
    debug_exportacion_simple(curso_id) 