from django.core.management.base import BaseCommand
from django.db import transaction
from home.models import Calificacion, Evaluacion, ResultadoRubrica, PuntajeCriterio, CriterioRubrica, Esperable


class Command(BaseCommand):
    help = 'Verifica y crea ResultadoRubrica faltantes para calificaciones existentes'

    def handle(self, *args, **options):
        self.stdout.write('Verificando calificaciones sin ResultadoRubrica...')
        
        # Obtener todas las calificaciones que tienen evaluación con rúbrica
        calificaciones = Calificacion.objects.filter(
            evaluacion__rubrica__isnull=False
        ).select_related('evaluacion', 'evaluacion__rubrica', 'estudiante')
        
        creados = 0
        actualizados = 0
        
        for calificacion in calificaciones:
            evaluacion = calificacion.evaluacion
            rubrica = evaluacion.rubrica
            
            # Verificar si existe ResultadoRubrica para esta calificación
            resultado_rubrica, created = ResultadoRubrica.objects.get_or_create(
                rubrica=rubrica,
                estudiante=calificacion.estudiante,
                defaults={
                    'evaluador': calificacion.calificado_por,
                    'puntaje_total': 0,
                    'nota_final': calificacion.nota
                }
            )
            
            if created:
                self.stdout.write(f'Creado ResultadoRubrica para calificación {calificacion.id}')
                creados += 1
                
                # Crear PuntajeCriterio para cada criterio (con valores por defecto)
                for criterio in rubrica.criterios.all():
                    # Obtener el primer esperable como valor por defecto
                    esperable_default = criterio.esperables.first()
                    
                    PuntajeCriterio.objects.create(
                        resultado_rubrica=resultado_rubrica,
                        criterio=criterio,
                        esperable_seleccionado=esperable_default,
                        puntaje_obtenido=esperable_default.puntaje if esperable_default else 0,
                        comentarios=''
                    )
            else:
                # Actualizar datos existentes
                resultado_rubrica.nota_final = calificacion.nota
                resultado_rubrica.evaluador = calificacion.calificado_por
                resultado_rubrica.save()
                actualizados += 1
        
        self.stdout.write(
            self.style.SUCCESS(
                f'Proceso completado. Creados: {creados}, Actualizados: {actualizados}'
            )
        ) 