from django.shortcuts import render,redirect
from django.views.generic import View
from django.contrib import messages
from validate_email import validate_email
from django.contrib.auth.models import User


##########################################################################
                    #main classes  
##########################################################################
class RegistrationView(View):
    def get(self,request):
        return render(request,'authentication/register.html')
    def post(self,request):
        data=request.POST
        context={
            'data':data,
            'has_error':False
        }
        email=data.get('email')
        password=data.get('password')
        password2=data.get('password2')
        username=data.get('username')
        fullname=data.get('name')
        if not validate_email(email):
            messages.add_message(request,messages.ERROR,"Please provide a valid email")
            context['has_error']=True
        if len(password)<6:
            messages.add_message(request,messages.ERROR,"Password has to have a mimimum leght of 6 characters ")
            context['has_error']=True
        if password != password2:
            messages.add_message(request,messages.ERROR,"Passwords do not match")
            context['has_error']=True
        if User.objects.filter(email=email).exists():
            messages.add_message(request,messages.ERROR,"Email already exists")
            context['has_error']=True
        if User.objects.filter(username=username).exists():
            messages.add_message(request,messages.ERROR,"Username already exists")
            context['has_error']=True
        if context['has_error']:
            return render(request,'authentication/register.html',context,status=400)
        user=User.objects.create_user(email=email,username=username)
        user.set_password(password)
        user.first_name=fullname
        user.last_name=fullname
        user.is_active=False
        user.save()
        messages.add_message(request,messages.SUCCESS,"Account Added Succesfully ")
        return redirect('login')

class LoginView(View):
    def get(self,request):
        return render(request,'authentication/login.html')
#logout
class ForgotPasswordView(View):
    def get(self,request):
        return render(request,'authentication/forgot_password.html')
#change password 
class HomeView(View):
    def get(self,request):
        return render(request,'home.html')
    

##############################################################################
                    #supporting classes 
##############################################################################