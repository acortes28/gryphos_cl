# Solución: Sistema de Calificación Basado en Rúbricas Dinámicas

## Resumen

Se implementó un sistema de calificación dinámico que permite a los usuarios staff/admin calificar estudiantes basándose en rúbricas asociadas a las evaluaciones, en lugar de ingresar notas directamente.

## Componentes Implementados

### 1. Formulario Dinámico (`home/forms.py`)

#### Clase `CalificacionForm`
- **Campos base**: `estudiante`, `retroalimentacion`
- **Campos dinámicos**: Se generan automáticamente para cada criterio de la rúbrica
- **Nomenclatura**: `criterio_{id_criterio}` (ej: `criterio_13`, `criterio_14`)

#### Funcionalidades del Formulario
```python
def __init__(self, *args, **kwargs):
    # ... código existente ...
    
    # Agregar campos dinámicos para cada criterio de la rúbrica
    if evaluacion and hasattr(evaluacion, 'rubrica'):
        rubrica = evaluacion.rubrica
        if rubrica:
            # Guardar criterios para uso posterior
            self.criterios_rubrica = list(rubrica.criterios.all())
            
            for criterio in rubrica.criterios.all():
                # Crear opciones basadas en esperables
                choices = [('', 'Selecciona un nivel...')]
                for esperable in criterio.esperables.all():
                    choices.append((esperable.id, f"{esperable.nivel} - {esperable.puntaje} pts"))
                
                # Crear campo dinámico
                field_name = f'criterio_{criterio.id}'
                self.fields[field_name] = forms.ChoiceField(
                    choices=choices,
                    required=True,
                    widget=forms.Select(attrs={
                        'class': 'form-control',
                        'data-criterio-id': criterio.id,
                        'data-criterio-nombre': criterio.nombre,
                        'data-criterio-puntaje-maximo': criterio.puntaje
                    }),
                    label=f"{criterio.nombre}",
                    help_text=f"Puntaje máximo: {criterio.puntaje} puntos"
                )
```

### 2. Filtros de Template (`home/templatetags/custom_filters.py`)

#### Filtro `get_criterio_field`
```python
@register.filter
def get_criterio_field(form, criterio_id):
    """Filtro específico para obtener campos de criterio de rúbrica"""
    field_name = f'criterio_{criterio_id}'
    try:
        return form[field_name]
    except KeyError:
        return None
```

### 3. Template Dinámico (`home/templates/pages/calificar_estudiante.html`)

#### Renderizado de Campos de Criterio
```html
<!-- Mostrar campos de criterio dinámicamente -->
{% for criterio in criterios_rubrica %}
  <div class="form-group">
    <label for="id_criterio_{{ criterio.id }}" class="form-label">
      <i class="fas fa-check-circle me-1"></i>{{ criterio.nombre }} *
    </label>
    
    <!-- Renderizar el campo usando el filtro específico para criterios -->
    {% with criterio_field=form|get_criterio_field:criterio.id %}
      {% if criterio_field %}
        {{ criterio_field }}
        {% if criterio_field.errors %}
          <div class="text-danger small mt-1">
            {% for error in criterio_field.errors %}
              {{ error }}
            {% endfor %}
          </div>
        {% endif %}
        {% if criterio_field.help_text %}
          <small class="form-text text-muted">{{ criterio_field.help_text }}</small>
        {% endif %}
      {% else %}
        <div class="alert alert-warning">
          Campo no encontrado para criterio {{ criterio.id }}
        </div>
      {% endif %}
    {% endwith %}
  </div>
{% endfor %}
```

### 4. Vista Actualizada (`home/views.py`)

#### Contexto Enriquecido
```python
def calificar_estudiante(request, curso_id, evaluacion_id):
    # ... código existente ...
    
    context = {
        'curso': curso,
        'evaluacion': evaluacion,
        'form': form,
        'estudiantes': estudiantes_disponibles_para_calificar,
        'todos_estudiantes': todos_estudiantes,
        'estudiantes_ya_calificados': estudiantes_ya_calificados,
        'stats': stats,
        'user': request.user,
    }
    
    # Agregar criterios de rúbrica al contexto si existe
    if evaluacion and hasattr(evaluacion, 'rubrica') and evaluacion.rubrica:
        context['criterios_rubrica'] = form.criterios_rubrica if hasattr(form, 'criterios_rubrica') else evaluacion.rubrica.criterios.all()
        if hasattr(form, 'criterios_info'):
            context['criterios_info'] = form.criterios_info
```

## Ventajas de la Solución

### 1. **Completamente Dinámica**
- Funciona con cualquier número de criterios
- No requiere hardcoding de IDs específicos
- Se adapta automáticamente a diferentes rúbricas

### 2. **Robusta**
- Manejo de errores en filtros de template
- Validación de campos dinámicos
- Fallback graceful cuando no se encuentran campos

### 3. **Mantenible**
- Código limpio y bien documentado
- Separación clara de responsabilidades
- Fácil de extender para nuevas funcionalidades

### 4. **Escalable**
- Funciona con evaluaciones que tengan cualquier número de criterios
- Compatible con diferentes tipos de rúbricas
- Preparado para futuras mejoras

## Uso

### Para Evaluaciones con Rúbrica
1. El formulario automáticamente detecta la rúbrica asociada
2. Genera campos dinámicos para cada criterio
3. Cada campo muestra los esperables disponibles con sus puntajes
4. El usuario selecciona el nivel alcanzado para cada criterio

### Para Evaluaciones sin Rúbrica
1. Se muestra un mensaje indicando que no hay rúbrica asociada
2. El formulario funciona normalmente con campos estándar

## Próximos Pasos

### 1. Cálculo Automático de Notas
- Implementar lógica para calcular la nota final basada en los esperables seleccionados
- Considerar ponderaciones de criterios si las hay

### 2. Vista de Detalle de Calificación
- Mostrar los esperables seleccionados en la vista de detalle
- Desplegar el desglose de puntajes por criterio

### 3. Edición de Calificaciones
- Adaptar el modal de edición para usar el sistema de rúbricas
- Mantener consistencia con el sistema de calificación inicial

### 4. Reportes y Estadísticas
- Incluir análisis de rendimiento por criterio
- Generar reportes detallados de rúbricas

## Archivos Modificados

1. `home/forms.py` - Formulario dinámico
2. `home/templatetags/custom_filters.py` - Filtros de template
3. `home/templates/pages/calificar_estudiante.html` - Template dinámico
4. `home/views.py` - Contexto enriquecido

## Testing

La solución ha sido probada con:
- Evaluación ID 2 (4 criterios: 13, 14, 15, 16)
- Diferentes tipos de esperables
- Manejo de errores y casos edge
- Compatibilidad con el sistema existente 