from django.urls import path
from . import views
from django.contrib.auth import views as auth_views
from django.http import HttpResponseNotFound

urlpatterns = [
    # Pages
    path('', views.index, name="index"),
    path('que-hacemos/', views.que_hacemos, name='que-hacemos'),
    path('quienes-somos/', views.quienes_somos, name='quienes-somos'),
    path('inscripcion-curso/', views.inscripcion_curso, name='inscripcion-curso'),

    # Usuario
    path('portal-cliente/', views.portal_cliente, name='user_space'),
    path('debug-session/', views.debug_session, name='debug_session'),
    path('test-auth/', views.test_auth, name='test_auth'),
    path('test-registration/', views.test_registration_form, name='test_registration'),

    # Authentication
    path('generate-registration-link/', views.generate_registration_link, name='generate-registration-link'),
    path('accounts/register/', views.registration, name='sign-up'),
    path('accounts/login/', views.UserLoginView.as_view(), name='login'),
    path('accounts/logout/', views.user_logout_view, name='logout'),
    #path('accounts/register/<uuid:link_uuid>/', views.registration, name='register'),
    path('accounts/password-change/', views.UserPasswordChangeView.as_view(), name='password_change'),
    path('accounts/password-change-done/', auth_views.PasswordChangeDoneView.as_view(
        template_name='accounts/password_change_done.html'
    ), name="password_change_done" ),
    path('accounts/password-reset/', views.UserPasswordResetView.as_view(), name='password_reset'),
    path('accounts/password-reset-confirm/<uidb64>/<token>/',
        views.UserPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('accounts/password-reset-done/', auth_views.PasswordResetDoneView.as_view(
        template_name='accounts/password_reset_done.html'
    ), name='password_reset_done'),
    path('accounts/password-reset-complete/', auth_views.PasswordResetCompleteView.as_view(
        template_name='accounts/password_reset_complete.html'
    ), name='password_reset_complete'),
    path('accounts/activate/<uidb64>/<token>/', views.activate_account, name='activate-account'),
    
    # Curso URLs
    path('curso/<int:curso_id>/', views.curso_detail, name='curso_detail'),
    path('curso/<int:curso_id>/plataforma/', views.plataforma_aprendizaje, name='plataforma_aprendizaje'),
    path('curso/<int:curso_id>/plataforma/foro/', views.plataforma_foro, name='plataforma_foro'),
    path('curso/<int:curso_id>/plataforma/foro/ajax/', views.plataforma_foro_ajax, name='plataforma_foro_ajax'),
    path('curso/<int:curso_id>/plataforma/foro/post/<int:post_id>/', views.plataforma_foro_post_detail, name='plataforma_foro_post_detail'),
    path('curso/<int:curso_id>/plataforma/foro/post/<int:post_id>/delete/', views.plataforma_foro_delete_post, name='plataforma_foro_delete_post'),
    #path('curso/<int:curso_id>/plataforma/foro/comment/<int:comment_id>/delete/', views.plataforma_foro_delete_comment, name='plataforma_foro_delete_comment'),
    path('curso/<int:curso_id>/plataforma/foro/crear/', views.plataforma_foro_create_post, name='plataforma_foro_create_post'),
    
    # Calificaciones URLs
    path('curso/<int:curso_id>/calificaciones/', views.plataforma_calificaciones, name='plataforma_calificaciones'),
    path('curso/<int:curso_id>/calificaciones/crear-evaluacion/', views.crear_evaluacion, name='crear_evaluacion'),
    path('curso/<int:curso_id>/calificaciones/calificar/<int:evaluacion_id>/', views.calificar_estudiante, name='calificar_estudiante'),
    path('curso/<int:curso_id>/calificaciones/detalle/<int:calificacion_id>/', views.ver_calificacion_detalle, name='ver_calificacion_detalle'),
    path('curso/<int:curso_id>/calificaciones/estadisticas/', views.estadisticas_curso, name='estadisticas_curso'),
    path('curso/<int:curso_id>/calificaciones/editar/<int:evaluacion_id>/', views.editar_evaluacion, name='editar_evaluacion'),
    path('curso/<int:curso_id>/calificaciones/eliminar/<int:evaluacion_id>/', views.eliminar_evaluacion, name='eliminar_evaluacion'),
    path('editar-calificacion/', views.editar_calificacion, name='editar_calificacion'),
    path('limpiar-retroalimentaciones/', views.limpiar_retroalimentaciones, name='limpiar_retroalimentaciones'),
    
    path('cursos/', views.cursos_list, name='cursos_list'),
    path('cursos/<int:curso_id>/', views.curso_detail_public, name='curso_detail_public'),
    
    # Perfil de Usuario
    path('mi-perfil/', views.mi_perfil, name='mi_perfil'),
    
    # Forum URLs
    path('forum/', views.forum_list, name='forum_list'),
    path('forum/post/<int:post_id>/', views.forum_post_detail, name='forum_post_detail'),
    path('forum/create/', views.forum_create_post, name='forum_create_post'),
    path('forum/post/<int:post_id>/delete/', views.forum_delete_post, name='forum_delete_post'),
    path('forum/comment/<int:comment_id>/delete/', views.forum_delete_comment, name='forum_delete_comment'),
    
    # Blog URLs
    path('blog/', views.blog_list, name='blog_list'),
    path('blog/post/<int:post_id>/', views.blog_post_detail, name='blog_post_detail'),
    path('blog/create/', views.blog_create_post, name='blog_create_post'),
    path('blog/post/<int:post_id>/delete/', views.blog_delete_post, name='blog_delete_post'),
    
    # Admin URLs
    path('admin/inscripciones/', views.admin_inscripciones, name='admin-inscripciones'),
    path('admin/inscripcion/<int:inscripcion_id>/', views.admin_inscripcion_detail, name='admin-inscripcion-detail'),
    path('admin/marcar-pagado/<int:inscripcion_id>/', views.admin_marcar_pagado, name='admin-marcar-pagado'),
    path('admin/cambiar-estado/<int:inscripcion_id>/', views.admin_cambiar_estado, name='admin-cambiar-estado'),
    path('admin/reenviar-correo/<int:inscripcion_id>/', views.admin_reenviar_correo, name='admin-reenviar-correo'),
    
    # Session management
    path('extend-session/', views.extend_session, name='extend_session'),

    # Jitsi URLs
    path('jitsi/generate-token/', views.generate_jitsi_token, name='jitsi-token'),
    path('join-meeting/<int:videollamada_id>/', views.join_meeting, name='join_meeting'),

    # Entregas URLs
    path('plataforma/curso/<int:curso_id>/entregas/ajax/', views.plataforma_entregas_ajax, name='plataforma_entregas_ajax'),
]
