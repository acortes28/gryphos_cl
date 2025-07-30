from django.core.management.base import BaseCommand
from home.models import ClasificacionTicket, SubclasificacionTicket


class Command(BaseCommand):
    help = 'Crea las clasificaciones iniciales para el sistema de tickets de soporte'

    def handle(self, *args, **options):
        clasificaciones_data = [
            {
                'nombre': 'Problemas Técnicos',
                'descripcion': 'Problemas relacionados con la plataforma, acceso, navegación, etc.',
                'subclasificaciones': [
                    'Acceso a la plataforma',
                    'Problemas de navegación',
                    'Errores del sistema',
                    'Problemas con archivos',
                    'Problemas de video/audio',
                    'Otros problemas técnicos'
                ]
            },
            {
                'nombre': 'Contenido del Curso',
                'descripcion': 'Consultas sobre el contenido, materiales, evaluaciones, etc.',
                'subclasificaciones': [
                    'Dudas sobre el contenido',
                    'Materiales de estudio',
                    'Evaluaciones y tareas',
                    'Calificaciones',
                    'Recursos adicionales',
                    'Otros temas del curso'
                ]
            },
            {
                'nombre': 'Administrativo',
                'descripcion': 'Consultas sobre inscripciones, pagos, certificados, etc.',
                'subclasificaciones': [
                    'Inscripción al curso',
                    'Pagos y facturación',
                    'Certificados',
                    'Cambios de horario',
                    'Cancelaciones',
                    'Otros temas administrativos'
                ]
            },
            {
                'nombre': 'Soporte General',
                'descripcion': 'Otras consultas y solicitudes de soporte',
                'subclasificaciones': [
                    'Información general',
                    'Sugerencias',
                    'Reportes de bugs',
                    'Solicitudes especiales',
                    'Otros'
                ]
            }
        ]

        for clasificacion_data in clasificaciones_data:
            clasificacion, created = ClasificacionTicket.objects.get_or_create(
                nombre=clasificacion_data['nombre'],
                defaults={
                    'descripcion': clasificacion_data['descripcion'],
                    'activa': True
                }
            )
            
            if created:
                self.stdout.write(
                    self.style.SUCCESS(f'Clasificación creada: {clasificacion.nombre}')
                )
            else:
                self.stdout.write(
                    self.style.WARNING(f'Clasificación ya existe: {clasificacion.nombre}')
                )
            
            for subclasificacion_nombre in clasificacion_data['subclasificaciones']:
                subclasificacion, sub_created = SubclasificacionTicket.objects.get_or_create(
                    clasificacion=clasificacion,
                    nombre=subclasificacion_nombre,
                    defaults={
                        'activa': True
                    }
                )
                
                if sub_created:
                    self.stdout.write(
                        self.style.SUCCESS(f'  - Subclasificación creada: {subclasificacion.nombre}')
                    )
                else:
                    self.stdout.write(
                        self.style.WARNING(f'  - Subclasificación ya existe: {subclasificacion.nombre}')
                    )

        self.stdout.write(
            self.style.SUCCESS('Clasificaciones de tickets inicializadas correctamente')
        ) 