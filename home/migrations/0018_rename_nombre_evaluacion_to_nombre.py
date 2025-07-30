# Generated manually to fix column name discrepancy

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0017_rename_tipo_evaluacion_to_tipo'),
    ]

    operations = [
        migrations.RunSQL(
            sql='ALTER TABLE home_evaluacion RENAME COLUMN nombre_evaluacion TO nombre;',
            reverse_sql='ALTER TABLE home_evaluacion RENAME COLUMN nombre TO nombre_evaluacion;',
        ),
    ] 