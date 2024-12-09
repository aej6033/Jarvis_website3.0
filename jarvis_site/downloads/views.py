from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import views as auth_views
from django.urls import path, include
from downloads import views as downloads_views
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash, authenticate, login
from django.contrib.auth.forms import PasswordChangeForm
from .forums import UpdateEmailForm, ChangePasswordForm, DeleteAccountForm
from django.contrib.auth.password_validation import validate_password
from django.core.validators import EmailValidator
from django.core.exceptions import ValidationError
def home(request):
    return render(request, 'downloads/home.html')

def downloads(request):
    return render(request, 'downloads/downloads.html')

@login_required
def forums(request):
    return render(request, 'forums/forums_home.html')


def create_account(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        email_confirm = request.POST.get('email_confirm')
        password = request.POST.get('password')
        password_confirm = request.POST.get('password_confirm')

        # Validate that emails match
        if email != email_confirm:
            messages.error(request, "Emails do not match.")
            return render(request, 'downloads/create_account.html', {
                'username': username,
                'email': email,
            })

        # Validate the email format
        email_validator = EmailValidator()
        try:
            email_validator(email)
        except ValidationError:
            messages.error(request, "Invalid email format.")
            return render(request, 'downloads/create_account.html', {
                'username': username,
                'email': email,
            })

        # Validate that passwords match
        if password != password_confirm:
            messages.error(request, "Passwords do not match.")
            return render(request, 'downloads/create_account.html', {
                'username': username,
                'email': email,
            })

        # Validate the password
        try:
            validate_password(password)
        except ValidationError as e:
            for error in e:
                messages.error(request, error)
            return render(request, 'downloads/create_account.html', {
                'username': username,
                'email': email,
            })

        # Check if the username already exists
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already taken.")
            return render(request, 'downloads/create_account.html', {
                'username': username,
                'email': email,
            })

        # Check if the email already exists
        if User.objects.filter(email=email).exists():
            messages.error(request, "An account with this email already exists.")
            return render(request, 'downloads/create_account.html', {
                'username': username,
                'email': email,
            })

        # Create the user
        user = User.objects.create_user(username=username, email=email, password=password)
        user.save()

        messages.success(request, "Account created successfully! Please log in.")
        return redirect('login')

    return render(request, 'downloads/create_account.html')

@login_required
def account_page(request):
    return render(request, 'downloads/account.html', {'user': request.user})

@login_required
def update_email(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        email_confirm = request.POST.get('email_confirm')

        # Validate that emails match
        if email != email_confirm:
            messages.error(request, "Emails do not match.")
            return render(request, 'downloads/update_email.html', {
                'email': email,
            })

        # Validate the email format
        email_validator = EmailValidator()
        try:
            email_validator(email)
        except ValidationError:
            messages.error(request, "Invalid email format.")
            return render(request, 'downloads/update_email.html', {
                'email': email,
            })

        # Check if the email already exists
        if User.objects.filter(email=email).exists():
            messages.error(request, "An account with this email already exists.")
            return render(request, 'downloads/update_email.html', {
                'email': email,
            })

        # Update the email
        user = request.user
        user.email = email
        user.save()

        messages.success(request, "Email updated successfully!")
        return redirect('account')
    
    # Render form with initial data
    return render(request, 'downloads/update_email.html', {
        'email': request.user.email,
    })

@login_required
def change_password(request):
    if request.method == 'POST':
        form = ChangePasswordForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Important: Keeps the user logged in
            messages.success(request, "Password changed successfully!")
            return redirect('account')
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        form = ChangePasswordForm(request.user)
    return render(request, 'downloads/change_password.html', {'form': form})

@login_required
def delete_account(request):
    if request.method == 'POST':
        form = DeleteAccountForm(request.POST)
        if form.is_valid():
            password = form.cleaned_data.get('password')
            user = authenticate(username=request.user.username, password=password)
            if user:
                user.delete()
                messages.success(request, "Your account has been deleted.")
                return redirect('/')
            else:
                messages.error(request, "Incorrect password.")
    else:
        form = DeleteAccountForm()
    return render(request, 'downloads/delete_account.html', {'form': form})