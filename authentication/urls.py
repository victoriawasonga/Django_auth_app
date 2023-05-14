from django.urls import path
from . import views 

urlpatterns = [
    path('register',views.RegistrationView.as_view(),name="register"),
    path('login',views.LoginView.as_view(),name="login"),
    path('forgot_password',views.ForgotPasswordView.as_view(),name="forgot_password"),
    path('activate/<uidb64>/<token>',views.ActivateAccountView.as_view(),name="activate"),
    path('',views.HomeView.as_view(),name="home"),
         ]