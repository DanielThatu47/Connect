# your_app_name/forms.py

from django import forms
from .models import User, Admin, NGO
from django.contrib.auth.models import User
from django.contrib.auth.forms import PasswordChangeForm
from mongoengine import Document
from mongoengine.fields import StringField, EmailField, ImageField  ,DateTimeField
from django.utils.translation import gettext_lazy as _

from datetime import datetime
import random
import bcrypt
def generate_random_color():
    return "#{:06x}".format(random.randint(0, 0xFFFFFF))

class User(Document):
    name = StringField(required=True, max_length=50)
    email = EmailField(required=True, unique=True)
    password = StringField(required=True)
    created_at = DateTimeField(default=datetime.utcnow)
    profile_color = StringField(default=generate_random_color)  # Ensure this field is defined
    avatar = ImageField()


    def set_password(self, raw_password):
        self.password = bcrypt.hashpw(raw_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, raw_password):
        return bcrypt.checkpw(raw_password.encode('utf-8'), self.password.encode('utf-8'))

class RegisterForm(forms.Form):
    name = forms.CharField(max_length=100,
                                 required=True,
                                 widget=forms.TextInput(attrs={'class':"bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-primary-600 focus:border-primary-600 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500",
                                    'placeholder':"Enter Your Name"
                                }))
   
   
    email = forms.EmailField(required=True,
                             widget=forms.EmailInput(attrs={ 'class':"bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-primary-600 focus:border-primary-600 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500",
                                  'placeholder':"name@mail.com"
                             }))
    
    
    
    password = forms.CharField(
        max_length=12,
        widget=forms.PasswordInput(attrs={
            'class': 'mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-800 dark:border-gray-700 dark:placeholder-gray-400 dark:text-white',
            'placeholder': 'Enter your password',
            'id': 'register-password'
        }),
        required=True
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-800 dark:border-gray-700 dark:placeholder-gray-400 dark:text-white',
            'placeholder': 'Confirm your password',
            'id': 'register-confirm-password'
        }),
        required=True
    )
    remember_me = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'w-4 h-4 text-blue-600 bg-gray-100 border-gray-300 rounded focus:ring-blue-500 dark:focus:ring-blue-600 dark:ring-offset-gray-800 focus:ring-2 dark:bg-gray-700 dark:border-gray-600',
            'id': 'remember-me'
        })
    )
    def clean(self):
        cleaned_data = super().clean()
        name = cleaned_data.get("name")
        password = cleaned_data.get("password")
        confirm_password = cleaned_data.get("confirm_password")
        
        # Check password length
        if len(password) < 8:
            self.add_error('password', "Password must be at least 8 characters long.")
        
        # Check if password is not the same as the name
        if password == name:
            self.add_error('password', "Password cannot be the same as the name.")

        # Check if password and confirm_password match
        if password != confirm_password:
            self.add_error('confirm_password', "Passwords do not match.")

        # Check if email already exists
        if User.objects(email=cleaned_data.get('email')).first():
            self.add_error('email', "Email is already registered , Try with the New Email")


        return cleaned_data

class LoginForm(forms.Form):
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'class': "bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-primary-600 focus:border-primary-600 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500",
            'placeholder': "name@mail.com",
            'id': 'login-email'
        })
    )
    password = forms.CharField(
        max_length=12,
        widget=forms.PasswordInput(attrs={
            'class': 'mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-800 dark:border-gray-700 dark:placeholder-gray-400 dark:text-white',
            'placeholder': 'Enter your password',
            'id': 'login-password'
        }),
        required=True
    )
    remember_me = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'w-4 h-4 text-blue-600 bg-gray-100 border-gray-300 rounded focus:ring-blue-500 dark:focus:ring-blue-600 dark:ring-offset-gray-800 focus:ring-2 dark:bg-gray-700 dark:border-gray-600',
            'id': 'remember-me'
        })
    )
    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get("email")
        password = cleaned_data.get("password")

        # Check if the user exists
        user = User.objects(email=email).first()
        if user is None:
            self.add_error('email', "Invalid email or password.")

        # Verify the password if the user exists
        elif not user.check_password(password):
            self.add_error('password', "Invalid email or password.")

        return cleaned_data
        

class AdminLoginForm(forms.Form):
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'class': "bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-primary-600 focus:border-primary-600 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500",
            'placeholder': "admin@example.com",
            'id': 'admin-login-email'
        })
    )
    password = forms.CharField(
        max_length=50,
        widget=forms.PasswordInput(attrs={
            'class': 'mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-800 dark:border-gray-700 dark:placeholder-gray-400 dark:text-white',
            'placeholder': 'Enter your password',
            'id': 'admin-login-password'
        }),
        required=True
    )

    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get("email")
        password = cleaned_data.get("password")

        # Check if the admin exists
        admin = Admin.objects(email=email).first()
        if admin is None:
            self.add_error('email', "Invalid email or password.")

        # Verify the password if the admin exists
        elif not admin.check_password(password):
            self.add_error('password', "Invalid email or password.")

        return cleaned_data
    



class NGOForm(forms.Form):
    name = forms.CharField(max_length=100, required=True, widget=forms.TextInput(attrs={
        'class': "bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-primary-600 focus:border-primary-600 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500",
        'placeholder': "NGO Name"
    }))
    
    description = forms.CharField(widget=forms.Textarea(attrs={
        'class': "bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-primary-600 focus:border-primary-600 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500",
        'placeholder': "NGO Description",
        'rows': 4
    }))
    vision = forms.CharField(widget=forms.Textarea(attrs={
        'class': "bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-primary-600 focus:border-primary-600 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500",
        'placeholder': "Add your vision here",
        'rows': 4
    }))
    mission = forms.CharField(widget=forms.Textarea(attrs={
        'class': "bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-primary-600 focus:border-primary-600 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500",
        'placeholder': "Add your mission here",
        'rows': 4
    }))
    contact_number = forms.CharField(widget=forms.TextInput(attrs={
        'class': "bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-primary-600 focus:border-primary-600 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500",
        'placeholder': "Add your contact number here",
        'rows': 4
    }))
    email = forms.EmailField(widget=forms.EmailInput(attrs={
        'class': "bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-primary-600 focus:border-primary-600 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500",
        'placeholder': "Add your email here",
        'rows': 4
    }))
    website = forms.URLField(widget=forms.URLInput(attrs={
        'class': "bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-primary-600 focus:border-primary-600 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500",
        'placeholder': "Add your website here",
        'rows': 4
    }))
    address = forms.CharField(max_length=200, required=True, widget=forms.TextInput(attrs={
        'class': "bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-primary-600 focus:border-primary-600 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500",
        'placeholder': "Add your address here"
    }))
    category = forms.CharField(max_length=50, required=True, widget=forms.TextInput(attrs={
        'class': "bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-primary-600 focus:border-primary-600 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500",
        'placeholder': "NGO Category"
    }))
    image = forms.ImageField(required=True, widget=forms.FileInput(attrs={
        'class': "block w-full text-sm text-gray-900 border border-gray-300 rounded-lg cursor-pointer bg-gray-50 dark:text-gray-400 focus:outline-none dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400",
        'accept': "image/*"
    }))

class ProfileForm(forms.Form):
    name = forms.CharField(max_length=150, required=True, widget=forms.TextInput(attrs={
        'class': "bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-primary-600 focus:border-primary-600 block w-full p-2.5",
        'placeholder': "Name",
        'disabled': 'disabled'  # Disable name field
    }))
    email = forms.EmailField(required=True, widget=forms.EmailInput(attrs={
        'class': "bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-primary-600 focus:border-primary-600 block w-full p-2.5",
        'placeholder': "Email"
    }))
 
    avatar = forms.ImageField(required=False, widget=forms.FileInput(attrs={
        'class': "hidden",  # Hidden file input
        'accept': "image/*",  # Only accept image files
        
    }))
    def __init__(self, *args, **kwargs):
        self.instance = kwargs.pop('instance', None)
        super(ProfileForm, self).__init__(*args, **kwargs)
        if self.instance:
            self.fields['email'].initial = self.instance.email
            self.fields['name'].initial = self.instance.name
            self.fields['avatar'].initial = self.instance.avatar

class ChangePasswordForm(forms.Form):
    old_password = forms.CharField(widget=forms.PasswordInput(), label=_("Old Password"))
    new_password1 = forms.CharField(widget=forms.PasswordInput(), label=_("New Password"))
    new_password2 = forms.CharField(widget=forms.PasswordInput(), label=_("Confirm New Password"))

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super(ChangePasswordForm, self).__init__(*args, **kwargs)

    def clean_old_password(self):
        old_password = self.cleaned_data.get('old_password')
        if not self.user.check_password(old_password):
            raise forms.ValidationError(_("Your old password was entered incorrectly. Please enter it again."))
        return old_password

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get('new_password1')
        password2 = cleaned_data.get('new_password2')

        if password1 and password2 and password1 != password2:
            raise forms.ValidationError(_("The two password fields didn't match."))

        return cleaned_data


class UpdateEmailForm(forms.Form):
    email = forms.EmailField(label=_("Email"), required=True)

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super(UpdateEmailForm, self).__init__(*args, **kwargs)

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exclude(id=self.user.id).exists():
            raise forms.ValidationError(_("This email is already in use."))
        return email



class PasswordResetRequestForm(forms.Form):
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'class': "bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-primary-600 focus:border-primary-600 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500",
            'placeholder': "name@mail.com",
            'id': 'reset-email'
        })
    )

class SetPasswordForm(forms.Form):
    password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-800 dark:border-gray-700 dark:placeholder-gray-400 dark:text-white',
            'placeholder': 'Enter new password',
            'id': 'new-password'
        }),
        label="New password"
    )
    password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-800 dark:border-gray-700 dark:placeholder-gray-400 dark:text-white',
            'placeholder': 'Confirm new password',
            'id': 'confirm-password'
        }),
        label="Confirm new password"
    )

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get('password1')
        password2 = cleaned_data.get('password2')
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Passwords don't match")
        return cleaned_data


