# Generated manually to add missing creado_por field

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0018_rename_nombre_evaluacion_to_nombre'),
    ]

    operations = [
        migrations.AddField(
            model_name='evaluacion',
            name='creado_por',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='evaluaciones_creadas', to=settings.AUTH_USER_MODEL, null=True),
        ),
    ] 