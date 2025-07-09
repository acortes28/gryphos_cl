from django.urls import path
from . import views
from django.contrib.auth import views as auth_views
from django.http import HttpResponseNotFound

urlpatterns = [
    # Pages
    path('', views.index, name="index"),
    path('que-hacemos/', views.que_hacemos, name='que-hacemos'),
    path('quienes-somos/', views.quienes_somos, name='quienes-somos'),

    # Usuario
    path('portal-cliente/', views.portal_cliente, name='user_space'),

    # Authentication
    path('generate-registration-link/', views.generate_registration_link, name='generate-registration-link'),
    path('accounts/login/', views.UserLoginView.as_view(), name='login'),
    path('accounts/logout/', views.user_logout_view, name='logout'),
    path('accounts/register/<uuid:link_uuid>/', views.registration, name='register'),
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

    #Páginas que excluir debido a que pertenecen al template de Materials Kit 2
    path('presentation/', lambda request: HttpResponseNotFound('Not found')),
    path('page-header/', lambda request: HttpResponseNotFound('Not found')),
    path('features/', lambda request: HttpResponseNotFound('Not found')),
    path('navbar/', lambda request: HttpResponseNotFound('Not found')),
    path('nav-tabs/', lambda request: HttpResponseNotFound('Not found')),
    path('pagination/', lambda request: HttpResponseNotFound('Not found')),
    path('forms/', lambda request: HttpResponseNotFound('Not found')),
    path('inputs/', lambda request: HttpResponseNotFound('Not found')),
    path('avatars/', lambda request: HttpResponseNotFound('Not found')),
    path('badges/', lambda request: HttpResponseNotFound('Not found')),
    path('breadcrumbs/', lambda request: HttpResponseNotFound('Not found')),
    path('buttons/', lambda request: HttpResponseNotFound('Not found')),
    path('dropdowns/', lambda request: HttpResponseNotFound('Not found')),
    path('progress-bars/', lambda request: HttpResponseNotFound('Not found')),
    path('toggles/', lambda request: HttpResponseNotFound('Not found')),
    path('typography/', lambda request: HttpResponseNotFound('Not found')),
    path('alerts/', lambda request: HttpResponseNotFound('Not found')),
    path('modals/', lambda request: HttpResponseNotFound('Not found')),
    path('tooltips/', lambda request: HttpResponseNotFound('Not found')),
    path('accounts/register/', lambda request: HttpResponseNotFound('Not found')),
    path('contact-us/', lambda request: HttpResponseNotFound('Not found')),
    path('about-us/', lambda request: HttpResponseNotFound('Not found')),
    path('author/', lambda request: HttpResponseNotFound('Not found')),
]
