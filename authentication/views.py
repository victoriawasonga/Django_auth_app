from django.shortcuts import render,redirect
from django.views.generic import View
from django.contrib import messages
from validate_email import validate_email
from django.contrib.auth.models import User


from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.utils.encoding import force_bytes,force_str,DjangoUnicodeDecodeError
#utils.py file in the project folder 
from .utils import generate_token
from django.core.mail import EmailMessage
from django.conf import settings

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
        #get the current domain 
        current_site=get_current_site(request)
        email_subject="Activate your account"
        message=render_to_string('authentication/activate.html',
                                 {
                                     'user':user,
                                     'domain':current_site.domain,
                                     'uid':urlsafe_base64_encode(force_bytes(user.pk)),
                                     'token':generate_token.make_token(user),
                                     #'protocol':request.scheme
                                 }
                                 )
        email_from=settings.EMAIL_HOST_USER
        emai_message=EmailMessage(
            email_subject,
            message,
            email_from,
            [email])
        emai_message.send()
        messages.add_message(request,messages.SUCCESS,"Account Added Succesfully ")
        return redirect('login')

class ActivateAccountView(View):
    def get(self,request,uidb64,token):
        try:
            uid=force_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(pk=uid)
        except Exception as identifier:
            user=None
        if user is not None and generate_token.check_token(user,token):
            user.is_active=True
            user.save()
            messages.add_message(request,messages.INFO,'account activated succesfully')
            return redirect('login')
        return render(request, 'authentication/activate_failed.html',status=401)

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