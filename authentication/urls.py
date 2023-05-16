from django.urls import path
from . import views 
from django.contrib.auth.decorators import login_required
urlpatterns = [
    path('register',views.RegistrationView.as_view(),name="register"),
    path('login',views.LoginView.as_view(),name="login"),
    path('logout',views.LogoutView.as_view(),name="logout"),
    path('request_reset_email',views.RequestResetView.as_view(),name="request_reset_email"),
    path('activate/<uidb64>/<token>',views.ActivateAccountView.as_view(),name="activate"),
    path('set_new_password/<uidb64>/<token>',views.SetNewPasswordView.as_view(),name="set_new_password"),
    path('',login_required(views.HomeView.as_view()),name="home"),
         ]