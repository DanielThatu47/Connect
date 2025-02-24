from django.shortcuts import render, redirect, get_object_or_404
from .forms import RegisterForm, LoginForm, AdminLoginForm, NGOForm, ProfileForm, ChangePasswordForm ,UpdateEmailForm
from django.views.decorators.cache import never_cache
from .models import User, Admin, NGO ,Donation
import logging
import os
from django.conf import settings
from .google_auth import get_google_auth_flow, get_google_user_info, create_or_get_user
# from django.urls import reverse
import time
import random
logger = logging.getLogger(__name__)
from django.views.decorators.csrf import csrf_protect ,csrf_exempt
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _
from django.http import Http404, JsonResponse ,HttpResponse ,FileResponse
import io

from django.views.decorators.http import require_POST
import re
from django.contrib.auth.password_validation import validate_password
import bcrypt
from django.db.models import Q
from mongoengine.queryset.visitor import Q
from django.contrib.auth.tokens import PasswordResetTokenGenerator
import six
import datetime
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image 
import razorpay
import cloudinary
import cloudinary.uploader


class CustomTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
            six.text_type(user.id) + six.text_type(timestamp) + 
            six.text_type(user.email)
        )

token_generator = CustomTokenGenerator()

@never_cache
def home(request):
    """Render the home page."""
    user_id = request.session.get('user_id')
    if user_id:
        # If the user is already authenticated, redirect them to the 'main' page
        return redirect('main')
    return render(request, 'Home.html')

@never_cache  # Ensure the browser doesn't cache this page
def about(request):
    """Render the About page."""
    user_id = request.session.get('user_id')
    user = User.objects(id=user_id).first() if user_id else None
    avatar_url = user.avatar if user.avatar else None
    
    return render(request, 'About.html', {'user': user, 'avatar_url': avatar_url})


@never_cache
def contactus(request):
    """Render the Contact Us page."""
    user_id = request.session.get('user_id')
    user = User.objects(id=user_id).first() if user_id else None
    avatar_url = user.avatar if user.avatar else None
    
    return render(request, 'contactus.html', {
        'user': user,
        'avatar_url': avatar_url
    })
# views.py

@never_cache
@csrf_protect
def register(request):
    """Handle user registration."""
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            # Check if the email already exists using MongoEngine
            email = form.cleaned_data['email']
            existing_user = User.objects(email=email).first()
            if existing_user:
                form.add_error('email', "This email is already registered.")
            else:
                try:
                    # Create and save the user
                    user = User(
                        name=form.cleaned_data['name'],
                        email=email
                    )
                    user.set_password(form.cleaned_data['password'])
                    user.save()

                    # Automatically log in the user after registration
                    request.session['user_id'] = str(user.id)

                    # Check if "Remember Me" is selected
                    if form.cleaned_data.get('remember_me'):
                        request.session.set_expiry(30 * 24 * 60 * 60)  # 30 days
                    else:
                        request.session.set_expiry(0)

                    return redirect('main')
                except Exception as e:
                    logger.error("Error saving user: %s", e)
                    print("Error saving user:", e)
        else:
            print(form.errors)
    else:
        form = RegisterForm()
    
    return render(request, 'register.html', {'form': form})

@never_cache
@csrf_protect
def login(request):
    """Handle user login with optional 'remember me' functionality."""
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            remember_me = request.POST.get('remember_me')

            user = User.objects(email=email).first()  # Retrieve user by email

            if user and user.check_password(password):  # Verify password
                request.session['user_id'] = str(user.id)  # Store user ID in session
                request.session['user_email'] = user.email
                # request.session['user_image'] = user.profile_image
                # return redirect('main')
                # If 'remember me' is checked, set session to persist
                if remember_me:
                    request.session.set_expiry(60 * 60 * 24 * 30)  # 30 days
                else:
                    request.session.set_expiry(0)  # Session expires on browser close

                return redirect('main')  # Redirect to 'main' view
            else:
                form.add_error(None, "Invalid email or password.")
        else:
            print(form.errors)
    else:
        form = LoginForm()

    return render(request, 'login.html', {'form': form})

@never_cache  # Prevent caching for main page
def main(request):
    """Main page for authenticated users."""
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')  # Redirect to login if user is not authenticated

    user = User.objects(id=user_id).first()  # Fetch the user from the database
    ngos = NGO.objects.all()
    all_categories = NGO.objects.distinct('category')
    avatar_url = user.avatar if user.avatar else None
    context = {
        'user': user,
        'ngos': ngos,
        'avatar_url': avatar_url,
        'all_categories': all_categories,
        'query': '',
        'selected_category': 'All',
    }
    
    return render(request, 'Main.html', context)

@never_cache  # Ensure logout page is not cached
def logout(request):
    """Log out the user."""
    request.session.flush()  # Clear the session
    return redirect('login')  # Redirect to login page after logout

@never_cache
@csrf_protect
def admin_login(request):
    if request.method == 'POST':
        form = AdminLoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']

            admin = Admin.objects(email=email).first()

            if admin and admin.check_password(password):
                request.session['admin_id'] = str(admin.id)
                request.session.set_expiry(60 * 60 * 24 * 30)# session stored for 30 days
                return redirect('admin_dashboard')
            else:
                form.add_error(None, "Invalid email or password.")
    else:
        form = AdminLoginForm()

    return render(request, 'admin_login.html', {'form': form})

@never_cache

def admin_dashboard(request):
    admin_id = request.session.get('admin_id')
    if not admin_id:
        return redirect('admin_login')

    admin = Admin.objects(id=admin_id).first()
    
    # Fetch data for the dashboard
    total_users = User.objects.count()
    total_ngos = NGO.objects.count()
    recent_users = User.objects.order_by('-created_at')[:5]
    all_ngos = NGO.objects.order_by('-created_at')

    # Add authentication method to recent users
    recent_users_with_auth = []
    for user in recent_users:
        auth_method = 'Google' if user.password is None else 'Email/Password'
        recent_users_with_auth.append({'user': user, 'auth_method': auth_method})

    context = {
        'admin': admin,
        'total_users': total_users,
        'total_ngos': total_ngos,
        'recent_users': recent_users_with_auth,
        'all_ngos': all_ngos,
    }

    return render(request, 'admin_dashboard.html', context)

@never_cache
def admin_logout(request):
    request.session.pop('admin_id', None)
    return redirect('admin_login')

@never_cache
def add_ngo(request):
    admin_id = request.session.get('admin_id')
    if not admin_id:
        return redirect('admin_login')

    if request.method == 'POST':
        form = NGOForm(request.POST, request.FILES)
        if form.is_valid():
            ngo = NGO(
                name=form.cleaned_data['name'],
                description=form.cleaned_data['description'],
                address=form.cleaned_data['address'],
                category=form.cleaned_data['category'],
                vision=form.cleaned_data['vision'],
                mission=form.cleaned_data['mission'],
                contact_number=form.cleaned_data['contact_number'],
                email=form.cleaned_data['email'],
                website=form.cleaned_data['website']
            )
            
            # Handle image upload to cloudinary
            if 'image' in request.FILES:
                try:
                    uploaded_image = cloudinary.uploader.upload(request.FILES['image'], folder="ngo_images/")
                    ngo.image = uploaded_image['secure_url']  # Save the URL in the database
                except Exception as e:
                    return JsonResponse({'success': False, 'message': f"Image upload failed: {str(e)}"}, status=500)

            ngo.save()
            return redirect('admin_dashboard')
    else:
        form = NGOForm()

    return render(request, 'add_ngo.html', {'form': form})


@never_cache
def edit_ngo(request, ngo_id):
    admin_id = request.session.get('admin_id')
    if not admin_id:
        return redirect('admin_login')

    # Fetch the NGO to edit
    try:
        ngo = NGO.objects.get(id=ngo_id)
    except NGO.DoesNotExist:
        return redirect('admin_dashboard')  # Redirect if NGO does not exist

    if request.method == 'POST':
        form = NGOForm(request.POST, request.FILES, initial={
            'name': ngo.name,
            'description': ngo.description,
            'address': ngo.address,
            'category': ngo.category,
            'vision': ngo.vision,
            'mission': ngo.mission,
            'contact_number': ngo.contact_number,
            'email': ngo.email,
            'website': ngo.website
        })
        if form.is_valid():
            # Update fields
            ngo.name = form.cleaned_data['name']
            ngo.description = form.cleaned_data['description']
            ngo.address = form.cleaned_data['address']
            ngo.category = form.cleaned_data['category']
            ngo.vision = form.cleaned_data['vision']
            ngo.mission = form.cleaned_data['mission']
            ngo.contact_number = form.cleaned_data['contact_number']
            ngo.email = form.cleaned_data['email']
            ngo.website = form.cleaned_data['website']
            
            if 'image' in request.FILES:
                try:
                    uploaded_image = cloudinary.uploader.upload(request.FILES['image'], folder="ngo_images/")
                    ngo.image = uploaded_image['secure_url']  # Update the Cloudinary URL
                except Exception as e:
                    return JsonResponse({'success': False, 'message': f"Image upload failed: {str(e)}"}, status=500)


            # Save updated NGO
            ngo.save()
            return redirect('admin_dashboard')
    else:
        form = NGOForm(initial={
            'name': ngo.name,
            'description': ngo.description,
            'address': ngo.address,
            'category': ngo.category,
            'vision': ngo.vision,
            'mission': ngo.mission,
            'contact_number': ngo.contact_number,
            'email': ngo.email,
            'website': ngo.website
        })

    return render(request, 'edit_ngo.html', {'form': form, 'ngo': ngo})


@never_cache
def delete_ngo(request, ngo_id):
    admin_id = request.session.get('admin_id')
    if not admin_id:
        return redirect('admin_login')

    try:
        ngo = NGO.objects.get(id=ngo_id)
    except NGO.DoesNotExist:
        raise Http404("NGO does not exist")
    
    # Check if the NGO has an image and delete it from Cloudinary
    if ngo.image:
        try:
            # Extract the public ID from the Cloudinary URL
            public_id = ngo.image.split('/')[-1].split('.')[0]
            cloudinary.uploader.destroy(f"ngo_images/{public_id}")  # Delete the image from Cloudinary
            ngo.image = None  # Clear the image field in the database
        except Exception as e:
            return JsonResponse({'success': False, 'message': f"Image deletion failed: {str(e)}"}, status=500)

    # Now delete the NGO from the database
    ngo.delete()

    return redirect('admin_dashboard')



def google_login(request):
    flow = get_google_auth_flow()
    authorization_url, state = flow.authorization_url(prompt='consent')
    request.session['google_auth_state'] = state
    return redirect(authorization_url)

def google_callback(request):
    state = request.session.pop('google_auth_state', None)
    flow = get_google_auth_flow()

    try:
        flow.fetch_token(code=request.GET.get('code'))
        credentials = flow.credentials
        user_info = get_google_user_info(credentials)

        user = create_or_get_user(user_info)

        request.session['user_id'] = str(user.id)
        request.session['user_email'] = user.email
        request.session['user_image'] = user_info.get('picture')  # Google profile picture
        return redirect('main')  # Redirect to main page after Google login
    except Exception as e:
        logger.error(f"Google authentication error: {str(e)}")
        return redirect('main')

@never_cache
def search_ngos(request):
    query = request.GET.get('q', '')
    category = request.GET.get('category', 'All')
    
    ngos = NGO.objects.all()

    if query:
        ngos = ngos.filter(name__icontains=query)
    
    if category and category != 'All':
        ngos = ngos.filter(category=category)
    
    user_id = request.session.get('user_id')
    user = User.objects(id=user_id).first()
    avatar_url = user.avatar if user.avatar else None
    
    all_categories = NGO.objects.distinct('category')
    
    context = {
        'user': user,
        'ngos': ngos,
        
        'avatar_url': avatar_url,
        'query': query,
        'all_categories': all_categories,
    }
    
    return render(request, 'Main.html', context)


import random

@never_cache
def some_view(request):
    user_id = request.session.get('user_id')
    user = User.objects(id=user_id).first() if user_id else None
    random_color = "#{:06x}".format(random.randint(0, 0xFFFFFF)) if user else None
    context = {
        'user': user,
        'random_color': random_color,
        # other context variables
    }
    return render(request, 'some_template.html', context)


@never_cache  # Ensure the browser doesn't cache this page

def ngoview(request):
    """Render the NGO page."""
    user_id = request.session.get('user_id')
    user = User.objects(id=user_id).first()
    return render(request, 'NGO.html', {'user': user})


@never_cache
def profile(request):
    user_id = request.session.get('user_id')
    user = User.objects(id=user_id).first()
    profile_form = None
    password_form = None
    email_form = None

    donations = Donation.objects(user=user_id)
    if not user_id or not user:
        return redirect('login')

    if request.method == 'POST':
        # Handle password change
        if 'change_password' in request.POST:
            if password_form.is_valid():
                user.set_password(password_form.cleaned_data['new_password1'])
                user.save()
                update_session_auth_hash(request, user)
                return JsonResponse({'success': True, 'message': 'Password updated successfully.'})
            else:
                return JsonResponse({'success': False, 'errors': password_form.errors})

        # Handle email update
        if 'update_email' in request.POST:
            if email_form.is_valid():
                user.email = email_form.cleaned_data['email']
                user.save()
                return JsonResponse({'success': True, 'message': 'Email updated successfully.'})
            else:
                return JsonResponse({'success': False, 'errors': email_form.errors})
    else:
        profile_form = ProfileForm(instance=user)
        password_form = ChangePasswordForm(user)
        email_form = UpdateEmailForm(user=user)

    # Directly use the Cloudinary URL
    avatar_url = user.avatar if user.avatar else None

    return render(request, 'profile.html', {
        'profile_form': profile_form,
        'password_form': password_form,
        'user': user,
        'email_form': email_form,
        'avatar_url': avatar_url,  # Directly pass the Cloudinary URL
        'donations': donations,
    })

@require_POST
def handle_avatar_upload(request):
    user_id = request.session.get('user_id')
    user = User.objects(id=user_id).first()
    
    if not user:
        return JsonResponse({'success': False, 'message': 'User not found'}, status=400)
    
    if 'avatar' not in request.FILES:
        return JsonResponse({'success': False, 'message': 'No avatar file provided'}, status=400)
    
    avatar = request.FILES['avatar']
    
    # Cloudinary automatically saves the file and returns the URL
    try:
        uploaded_avatar = cloudinary.uploader.upload(avatar, folder="avatars/")
        user.avatar = uploaded_avatar['secure_url']  # Save the Cloudinary URL in the model
        user.save()
        return JsonResponse({
            'success': True,
            'message': 'Avatar uploaded successfully.',
            'avatar_url': user.avatar,
        })
    except Exception as e:
        return JsonResponse({'success': False, 'message': f"Upload failed: {str(e)}"}, status=500)


@require_POST
def delete_avatar(request):
    user_id = request.session.get('user_id')
    user = User.objects(id=user_id).first()

    if not user:
        return JsonResponse({'success': False, 'message': 'User not found'}, status=400)

    if user.avatar:
        try:
            # Extract the public ID from the Cloudinary URL
            public_id = user.avatar.split('/')[-1].split('.')[0]
            cloudinary.uploader.destroy(f"avatars/{public_id}")

            # Clear the avatar field in the user model
            user.avatar = None
            user.save()

            return JsonResponse({'success': True, 'message': 'Avatar deleted successfully.'})
        except Exception as e:
            return JsonResponse({'success': False, 'message': f"Failed to delete avatar: {str(e)}"}, status=500)
    else:
        return JsonResponse({'success': False, 'message': 'No avatar to delete.'}, status=400)


from django.views.decorators.http import require_POST
from django.http import JsonResponse

@require_POST
def update_email(request):
    user_id = request.session.get('user_id')
    user = User.objects(id=user_id).first()

    if not user:
        return JsonResponse({'success': False, 'message': 'User not found'}, status=400)

    new_email = request.POST.get('email')

    if not new_email:
        return JsonResponse({'success': False, 'message': 'Email is required'}, status=400)

    if new_email == user.email:
        return JsonResponse({'success': False, 'message': 'New email is the same as the current email'}, status=400)

    existing_user = User.objects(email=new_email).first()
    if existing_user and existing_user.id != user.id:
        return JsonResponse({'success': False, 'message': 'This email is already in use'}, status=400)

    user.email = new_email
    user.save()

    return JsonResponse({
        'success': True,
        'message': 'Email updated successfully',
        'new_email': new_email
    })

@require_POST
def update_password(request):
    user_id = request.session.get('user_id')
    user = User.objects(id=user_id).first()

    if not user:
        return JsonResponse({'success': False, 'message': _('User not found')}, status=400)

    old_password = request.POST.get('old_password')
    new_password = request.POST.get('new_password')
    confirm_password = request.POST.get('confirm_password')

    # Check if old password is correct
    if not bcrypt.checkpw(old_password.encode('utf-8'), user.password.encode('utf-8')):
        return JsonResponse({'success': False, 'message': _('Incorrect old password')}, status=400)

    # Check if new password and confirm password match
    if new_password != confirm_password:
        return JsonResponse({'success': False, 'message': _('New passwords do not match')}, status=400)

    # Validate new password
    try:
        validate_password(new_password, user)
    except ValidationError as e:
        return JsonResponse({'success': False, 'message': _(', '.join(e.messages))}, status=400)

    # Additional custom password validations
    if len(new_password) < 8:
        return JsonResponse({'success': False, 'message': _('Password must be at least 8 characters long')}, status=400)

    if user.name.lower() in new_password.lower():
        return JsonResponse({'success': False, 'message': _('Password cannot contain your name')}, status=400)

    if not re.search(r'[A-Z]', new_password):
        return JsonResponse({'success': False, 'message': _('Password must contain at least one uppercase letter')}, status=400)

    if not re.search(r'[a-z]', new_password):
        return JsonResponse({'success': False, 'message': _('Password must contain at least one lowercase letter')}, status=400)

    if not re.search(r'\d', new_password):
        return JsonResponse({'success': False, 'message': _('Password must contain at least one number')}, status=400)

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password):
        return JsonResponse({'success': False, 'message': _('Password must contain at least one special character')}, status=400)

    # Hash the new password
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

    # Update user's password
    user.password = hashed_password.decode('utf-8')
    user.save()

    return JsonResponse({
        'success': True,
        'message': _('Password updated successfully')
    })




from django.shortcuts import render, redirect
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib import messages
from .forms import PasswordResetRequestForm, SetPasswordForm
from .models import User  # Import your User model

def password_reset_request(request):
    if request.method == 'POST':
        form = PasswordResetRequestForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                user = User.objects(email=email).first()
                if user:
                    # Generate token using custom token generator
                    token = token_generator.make_token(user)
                    uid = urlsafe_base64_encode(force_bytes(str(user.id)))
                    
                    # Build reset link
                    reset_link = request.build_absolute_uri(
                        f'/password-reset-confirm/{uid}/{token}/'
                    )
                    
                    # Return success response with data needed for EmailJS
                    return JsonResponse({
                        'success': True,
                        'data': {
                            'email': email,
                            'reset_link': reset_link,
                            'user_name': user.name
                        }
                    })
                else:
                    return JsonResponse({
                        'success': False,
                        'message': 'No user found with this email address.'
                    })
            except Exception as e:
                logger.error(f"Password reset error: {str(e)}")
                return JsonResponse({
                    'success': False,
                    'message': 'An error occurred while processing your request.'
                })
    else:
        form = PasswordResetRequestForm()
    
    return render(request, 'password_reset_form.html', {'form': form})

def password_reset_success(request):
    return render(request, 'password_reset_success.html')


def password_reset_confirm(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects(id=uid).first()  # Use MongoEngine's query syntax
    except (TypeError, ValueError):
        user = None

    if user is not None and token_generator.check_token(user, token):
        if request.method == 'POST':
            form = SetPasswordForm(request.POST)
            if form.is_valid():
                # Set new password
                password = form.cleaned_data['password1']
                user.set_password(password)
                user.save()
                messages.success(request, 'Password has been reset successfully.')
                return redirect('login')
        else:
            form = SetPasswordForm()
        return render(request, 'password_reset_confirm.html', {'form': form})
    else:
        messages.error(request, 'Password reset link is invalid or has expired.')
        return redirect('login')

@never_cache
def ngo_detail(request, ngo_id):
    """Display detailed information about a specific NGO."""
    try:
        ngo = NGO.objects.get(id=ngo_id)
    except NGO.DoesNotExist:
        raise Http404("NGO not found")
    
    user_id = request.session.get('user_id')
    user = User.objects(id=user_id).first() if user_id else None
    avatar_url = None
    
    if user and user.avatar:
        avatar_url = request.build_absolute_uri(settings.MEDIA_URL + user.avatar)
    
    context = {
        'ngo': ngo,
        'user': user,
        'avatar_url': avatar_url,
        'MEDIA_URL': settings.MEDIA_URL,
    }
    
    return render(request, 'ngo_detail.html', context)

razorpay_client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

def donate(request, ngo_id):
    ngo = NGO.objects.get(id=ngo_id)
    user_id = request.session.get('user_id')
    user = User.objects(id=user_id).first() if user_id else None
    avatar_url = user.avatar if user.avatar else None
    context = {
        'ngo': ngo,
        'user': user,
        'avatar_url': avatar_url,
       
    }

    if request.method == "POST":
        amount = int(request.POST.get('amount')) * 100  # Convert to paise
        message = request.POST.get('message', '')
        
        # Create Razorpay Order
        razorpay_order = razorpay_client.order.create({
            "amount": amount,  # in paise
            "currency": "INR",
            "payment_capture": "1"
        })

        # Store order details temporarily
        request.session['donation_details'] = {
            "ngo_id": str(ngo_id),
            "amount": amount // 100,  # Convert back to INR for display
            "message": message,
            "razorpay_order_id": razorpay_order['id']
        }

        context.update({
            'order_id': razorpay_order['id'],
            'amount': amount // 100,
            'razorpay_key': settings.RAZORPAY_KEY_ID,
        })
        return render(request, 'donation_payment.html', context)

    return render(request, 'donate.html', context)


@csrf_exempt
def payment_success(request):
    if request.method == "POST":
        response_data = request.POST
        razorpay_order_id = response_data.get('razorpay_order_id')
        razorpay_payment_id = response_data.get('razorpay_payment_id')

        # Retrieve donation details
        donation_details = request.session.pop('donation_details', None)
        if not donation_details:
            return HttpResponse("Donation details not found.", status=400)

        try:
            ngo = NGO.objects.get(id=donation_details['ngo_id'])
            user_id = request.session.get('user_id')
            user = User.objects(id=user_id).first()

            # Save donation in database
            donation = Donation.objects.create(
                user=user,
                ngo=ngo,
                amount=donation_details['amount'],
                message=donation_details['message']
            )

            # Generate and save the receipt PDF
            receipt_path = os.path.join(settings.MEDIA_ROOT, 'receipts')
            os.makedirs(receipt_path, exist_ok=True)
            receipt_file = os.path.join(receipt_path, f"receipt_{donation.id}.pdf")

            generate_receipt(donation, ngo, receipt_file)

            # Optionally: Save receipt file path in donation (if needed)
            # donation.receipt_path = receipt_file
            # donation.save()

        except Exception as e:
            return HttpResponse(f"Error saving donation: {str(e)}", status=500)

        # Redirect to profile page
        return redirect('profile')

    return HttpResponse("Invalid request method.", status=400)

def generate_receipt(donation, ngo, receipt_file):
    """Generates a PDF receipt and saves it to the specified file."""
    doc = SimpleDocTemplate(receipt_file, pagesize=letter)
    elements = []

    # Add NGO Logo
    if ngo.image:  # Assuming 'image' is a field in the NGO model
        logo_path = os.path.join(settings.MEDIA_ROOT, ngo.image)
        elements.append(Image(logo_path, width=120, height=120))

    # Add Header
    styles = getSampleStyleSheet()
    title_style = styles['Heading1']
    title_style.textColor = colors.HexColor("#4A90E2")
    elements.append(Paragraph(f"Donation Receipt - {ngo.name}", title_style))
    elements.append(Spacer(1, 12))

    # Add Donation Details
    body_style = styles['BodyText']
    elements.append(Paragraph(f"<b>NGO Name:</b> {ngo.name}", body_style))
    elements.append(Paragraph(f"<b>Donor Name:</b> {donation.user.name}", body_style))
    elements.append(Paragraph(f"<b>Amount Donated:</b> `₹`{donation.amount}", body_style))
    elements.append(Paragraph(f"<b>Message:</b> {donation.message or 'N/A'}", body_style))
    elements.append(Paragraph(f"<b>Date & Time:</b> {donation.donated_at.strftime('%Y-%m-%d %H:%M:%S')}", body_style))
    elements.append(Spacer(1, 12))

    # Add NGO Description
    elements.append(Paragraph(f"<b>About NGO:</b> {ngo.description}", body_style))
    elements.append(Spacer(1, 12))

    # Footer
    footer_style = styles['Italic']
    footer_style.textColor = colors.HexColor("#555555")
    elements.append(Paragraph("Thank you for supporting our cause!", footer_style))

    # Build the PDF
    doc.build(elements)



import base64



@never_cache
def view_receipt(request, donation_id):
    user_id = request.session.get('user_id')
    user = User.objects(id=user_id).first()
    if not user:
        return redirect('login')

    try:
        donation = Donation.objects.get(id=donation_id, user=user)
    except Donation.DoesNotExist:
        return HttpResponse('Receipt not found.', status=404)

    # Generate the receipt PDF into a buffer
    receipt_buffer = io.BytesIO()
    generate_receipt(donation, donation.ngo, receipt_buffer)
    receipt_buffer.seek(0)
    
    # Base64-encode the PDF data
    pdf_data = base64.b64encode(receipt_buffer.getvalue()).decode('ascii')

    # Tailwind CSS and a PDF icon (SVG) are added for styling.
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Receipt - {donation.ngo.name}</title>
      <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-100">
      <div class="container mx-auto px-4 py-8">
        <div class="bg-white rounded-lg shadow-lg p-6">
          <div class="flex items-center mb-4">
            <!-- PDF Icon -->
            <svg class="w-12 h-12 text-red-500 mr-4" fill="currentColor" viewBox="0 0 24 24">
              <path d="M19 2H8a2 2 0 00-2 2v4H5a2 2 0 00-2 2v10a2 2 0 002 2h14a2 2 0 002-2V4a2 2 0 00-2-2zM8 4h11v5h-4a1 1 0 01-1-1V4zm11 16H5V10h1v2h12v-2h1z"/>
            </svg>
            <h1 class="text-2xl font-bold text-gray-800">Receipt - {donation.ngo.name}</h1>
          </div>
          <div class="mb-6">
            <embed class="w-full h-96 border rounded" src="data:application/pdf;base64,{pdf_data}" type="application/pdf">
          </div>
          <div class="flex justify-end">
            <a href="data:application/pdf;base64,{pdf_data}" download="receipt.pdf">
              <button class="bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-4 rounded inline-flex items-center">
                <!-- Download Icon -->
                <svg class="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                  <path d="M3 14a1 1 0 011-1h3v-4a1 1 0 112 0v4h3a1 1 0 110 2H5a1 1 0 01-1-1z"/>
                  <path d="M9 2a1 1 0 011 1v8.586l1.293-1.293a1 1 0 111.414 1.414l-3 3a1 1 0 01-1.414 0l-3-3a1 1 0 111.414-1.414L9 11.586V3a1 1 0 011-1z"/>
                </svg>
                <span>Download Receipt</span>
              </button>
            </a>
          </div>
        </div>
      </div>
    </body>
    </html>
    """
    return HttpResponse(html_content)