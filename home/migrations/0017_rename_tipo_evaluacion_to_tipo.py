# Generated manually to fix column name discrepancy

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0016_evaluacion_calificacion'),
    ]

    operations = [
        migrations.RunSQL(
            sql='ALTER TABLE home_evaluacion RENAME COLUMN tipo_evaluacion TO tipo;',
            reverse_sql='ALTER TABLE home_evaluacion RENAME COLUMN tipo TO tipo_evaluacion;',
        ),
    ] 