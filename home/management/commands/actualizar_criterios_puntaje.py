from django.core.management.base import BaseCommand
from home.models import CriterioRubrica, Esperable
from decimal import Decimal

class Command(BaseCommand):
    help = 'Actualiza los criterios existentes que no tienen puntaje asignado'

    def handle(self, *args, **options):
        # Obtener criterios que no tienen puntaje o tienen puntaje 0
        criterios_sin_puntaje = CriterioRubrica.objects.filter(
            puntaje__isnull=True
        ) | CriterioRubrica.objects.filter(puntaje=0)
        
        self.stdout.write(f"Encontrados {criterios_sin_puntaje.count()} criterios sin puntaje")
        
        # Actualizar todos los criterios y sus esperables
        criterios = CriterioRubrica.objects.all()
        self.stdout.write(f"Procesando {criterios.count()} criterios")
        
        for criterio in criterios:
            esperables = criterio.esperables.all()
            puntaje_total = 0
            
            if esperables.exists():
                # Asignar puntajes a los esperables si no los tienen
                for i, esperable in enumerate(esperables):
                    if esperable.puntaje == 0:
                        # Asignar puntaje basado en el orden (más puntos para niveles más altos)
                        if i == 0:  # Primer nivel
                            esperable.puntaje = Decimal('5.0')
                        elif i == 1:  # Segundo nivel
                            esperable.puntaje = Decimal('8.0')
                        elif i == 2:  # Tercer nivel
                            esperable.puntaje = Decimal('10.0')
                        else:  # Niveles adicionales
                            esperable.puntaje = Decimal('12.0')
                        
                        esperable.save()
                        self.stdout.write(
                            f'  Esperable "{esperable.nivel}" actualizado con {esperable.puntaje} puntos'
                        )
                    
                    puntaje_total += esperable.puntaje
                
                # Actualizar el puntaje total del criterio
                criterio.puntaje = puntaje_total
                criterio.save()
                
                self.stdout.write(
                    self.style.SUCCESS(
                        f'Criterio "{criterio.nombre}" actualizado con {puntaje_total} puntos totales'
                    )
                )
            else:
                # Si no hay esperables, asignar un puntaje por defecto
                criterio.puntaje = Decimal('10.0')
                criterio.save()
                
                self.stdout.write(
                    self.style.WARNING(
                        f'Criterio "{criterio.nombre}" sin esperables, asignado 10 puntos por defecto'
                    )
                )
        
        self.stdout.write(
            self.style.SUCCESS('Proceso completado exitosamente')
        ) 