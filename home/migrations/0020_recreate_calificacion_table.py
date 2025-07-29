# Generated manually to recreate calificacion table with correct structure

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0019_add_creado_por_to_evaluacion'),
    ]

    operations = [
        migrations.CreateModel(
            name='Calificacion',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('nota', models.DecimalField(blank=True, decimal_places=2, help_text='Nota obtenida', max_digits=5, null=True)),
                ('retroalimentacion', models.TextField(blank=True, help_text='Retroalimentación para el estudiante', null=True)),
                ('fecha_calificacion', models.DateTimeField(auto_now_add=True)),
                ('fecha_modificacion', models.DateTimeField(auto_now=True)),
                ('calificado_por', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='calificaciones_asignadas', to=settings.AUTH_USER_MODEL)),
                ('estudiante', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='calificaciones', to=settings.AUTH_USER_MODEL)),
                ('evaluacion', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='calificaciones', to='home.evaluacion')),
            ],
            options={
                'verbose_name': 'Calificación',
                'verbose_name_plural': 'Calificaciones',
                'ordering': ['-fecha_calificacion'],
                'unique_together': {('evaluacion', 'estudiante')},
            },
        ),
    ] 