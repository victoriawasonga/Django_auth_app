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
from django.contrib.auth import authenticate,login,logout
from django.contrib.auth.tokens import PasswordResetTokenGenerator
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
    def post(self,request):
        context={
            'data':request.POST,
            'has_error':False
        }
        username=request.POST.get('username')
        password=request.POST.get('password')
        if username =='' or  password =='':
            messages.add_message(request,messages.ERROR,'Username and Password is required')
            context['has_error']=True
        user=authenticate(request,username=username,password=password)
        if not user:
             messages.add_message(request,messages.ERROR,'Invalid credentials')
             context['has_error']=True
        if context['has_error']:
            return render(request,'authentication/login.html',status=401,context=context)
        login(request,user)
        return redirect('home')

#logout
class LogoutView(View):
    def post(self, request):
        logout(request)
        messages.add_message(request, messages.SUCCESS, 'Logout successfully')
        return redirect('login')
#change password 
class HomeView(View):
    def get(self,request):
        return render(request,'home.html')

class RequestResetView(View):
    def get(self, request):
        return render(request,'authentication/request_reset_email.html')
    def post(self, request):
        email=request.POST['email']
        if not validate_email(email):
            messages.add_message(request,messages.ERROR,'Invalid Email adress')
            return render(request,'authentication/request_reset_email.html')
        user=User.objects.filter(email=email)
        if user.exists():
            #get the current domain 
            current_site=get_current_site(request)
            email_subject="Reset your password"
            message=render_to_string('authentication/reset_user_password.html',
                                    {
                                        'domain':current_site.domain,
                                        'uid':urlsafe_base64_encode(force_bytes(user[0].pk)),
                                        'token':PasswordResetTokenGenerator().make_token(user[0]),
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
        messages.add_message(request,messages.ERROR,'We have sent you an email with instructuons on how to reset your password  ')
        return render(request,'authentication/request_reset_email.html')
    

class SetNewPasswordView(View):
    def get(self,request,uidb64,token):
        context={
            'uidb64':uidb64,
            'token':token
        }
        return render(request,'authentication/forgot_password.html',context)
    def post(self,request,uidb64,token):
        context={
            'uidb64':uidb64,
            'token':token,
            'has_error':False
        }
        data=request.POST
        password=data.get('password')
        password2=data.get('password2')
        if len(password)<6:
            messages.add_message(request,messages.ERROR,"Password has to have a mimimum leght of 6 characters ")
            context['has_error']=True
        if password != password2:
            messages.add_message(request,messages.ERROR,"Passwords do not match")
            context['has_error']=True
        if context['has_error']:
            return render(request,'authentication/forgot_password.html',context,status=400)
        try:
            user_id=force_str(urlsafe_base64_decode(uidb64))
        except DjangoUnicodeDecodeError as identifier:
            messages.error(request,"something went wrong")
            return render(request,'authentication/forgot_password.html',context)
        user=User.objects.get(pk=user_id)
        user.set_password(password)
        user.save()
        messages.success(request,'Password reset success, you can login with new password')
        return redirect('login')
