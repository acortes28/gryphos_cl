from django.shortcuts import render, redirect
from .forms import LoginForm, RegistrationForm, UserPasswordResetForm, UserSetPasswordForm, UserPasswordChangeForm
from django.contrib.auth import logout
from django.contrib.auth import views as auth_views
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from .models import RegistrationLink
from django.http import JsonResponse
import uuid

User = get_user_model()  # Obtener el modelo de usuario personalizado

def generate_registration_link(request):
    if request.user.is_superuser:
        new_link = RegistrationLink.objects.create(creator=request.user)
        return JsonResponse({'link': str(new_link.uuid)})
    else:
        return JsonResponse({'error': 'Unauthorized'}, status=403)

def registration(request, link_uuid):
    try:
        registration_link = RegistrationLink.objects.get(uuid=link_uuid, is_used=False)
    except RegistrationLink.DoesNotExist:
        return HttpResponse('Invalid or expired registration link.', status=404)

    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            registration_link.is_used = True
            registration_link.save()
            print('Account created successfully!')
            return redirect('/accounts/login/')
        else:
            print("Registration failed!")
    else:
        form = RegistrationForm()
    context = {'form': form}
    return render(request, 'accounts/sign-up.html', context)

class UserLoginView(auth_views.LoginView):
    template_name = 'accounts/sign-in.html'
    form_class = LoginForm
    success_url = '/'

class UserPasswordResetView(auth_views.PasswordResetView):
    template_name = 'accounts/password_reset.html'
    form_class = UserPasswordResetForm
class UserPasswordResetConfirmView(auth_views.PasswordResetConfirmView):
    template_name = 'accounts/password_reset_confirm.html'
    form_class = UserSetPasswordForm
class UserPasswordChangeView(auth_views.PasswordChangeView):
    template_name = 'accounts/password_change.html'
    form_class = UserPasswordChangeForm
def user_logout_view(request):
    logout(request)
    return redirect('/accounts/login/')

def index(request):
    return render(request, 'pages/index.html')

def que_hacemos(request):
    return render(request, 'pages/que-hacemos.html')

def quienes_somos(request):
    return render(request, 'pages/quienes-somos.html')

@login_required
def portal_cliente(request):
    return render(request, 'pages/portal-cliente.html')