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
]
