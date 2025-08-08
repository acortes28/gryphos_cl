from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.utils.translation import gettext as _
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import TemplateView
from home.models import Curso, Recurso, Evaluacion
from django.shortcuts import get_object_or_404, redirect, render
from django.contrib import messages
from django.template.loader import render_to_string
from django.conf import settings
import logging


# -*- coding: utf-8 -*-
"""
    vistas/recursos_views.py
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    Módulo que contiene las vistas relacionadas con los recursos de los cursos.
"""

logger = logging.getLogger(__name__)    
# ============================================================================
# VISTAS DEL SISTEMA DE RECURSOS
# ============================================================================
class PlataformaRecursosView(TemplateView):

    template_name = 'home/templates/pages/plataforma_recursos_content.html'
    response_no_access = {'error': "No tienes acceso a este curso."}
    response_no_permission = {'error': "No tienes permiso para acceder a este recurso."}


    def plataforma_recursos_ajax(self, request, curso_id):

        """
        Vista para manejar solicitudes AJAX relacionadas con los recursos de un curso.
        :param request: HttpRequest object
        :param curso_id: ID del curso cuyos recursos se desean manejar
        :return: JsonResponse con los datos procesados
        """
        logger.info(f"Accediendo a los recursos del curso con ID: {curso_id} por el usuario: {request.user.username}")

        obj_curso = get_object_or_404(Curso, id=curso_id, activo=True)

        if obj_curso not in request.user.cursos.all():
            messages.error(request, self.response_no_access['error'])
            return redirect('user_space')

        action = request.GET.get("action")

        context = {
            'user': request.user,
            'curso': obj_curso,
            'recursos': Recurso.objects.filter(curso=obj_curso, activo=True).order_by('-fecha_creacion'),
        }
            
        obj_recursos_con_evaluaciones = Recurso.objects.filter(curso=obj_curso, activo=True, evaluacion__isnull=False).distinct()
        obj_evaluaciones_con_recurso = Evaluacion.objects.filter(curso=obj_curso, activo=True, recurso__in=obj_recursos_con_evaluaciones).order_by('-fecha_creacion')

        context['evauaciones_con_recurso' ] = obj_evaluaciones_con_recurso
        
        # Si el usuario es staff o superusuario, se muestran las evaluaciones
        if request.user.is_staff or request.user.is_superuser:
            context['evaluaciones'] = Evaluacion.objects.filter(curso=obj_curso, activo=True).order_by('-fecha_creacion')


        return render(request, self.template_name, context)
