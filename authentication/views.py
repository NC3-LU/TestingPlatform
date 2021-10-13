from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate, update_session_auth_hash
from django.http import HttpResponseRedirect
from decouple import config

from .forms import SignUpForm, LoginForm, UserUpdateForm, ChangePasswordForm, SubscriptionRequestForm, UserDomainForm
from .models import SubscriptionRequest

from .forms import SignUpForm, LoginForm, UserUpdateForm, ChangePasswordForm
from iot_inspector.models import IOTUser

from iot_inspector_client import Client


def signup(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            form.save()
            clean_form = form.cleaned_data
            username = clean_form.get('username')
            raw_password = clean_form.get('password1')
            user = authenticate(username=username,  password=raw_password)
            login(request, user)
            messages.success(request, 'Your signed up successfully!')
            iotuser = IOTUser(user=user)
            iotuser.save()
            return redirect('/')
    else:
        form = SignUpForm()
    return render(request, 'signup.html', {'form': form})


def login_user(request):
    if request.method == 'POST':
        form = LoginForm(data=request.POST)
        if form.is_valid():
            username = request.POST['username']
            password = request.POST['password']
            user = authenticate(request=request, username=username, password=password)
            if user is not None:
                login(request, user)
                messages.success(request, 'Your logged in successfully!')
                return HttpResponseRedirect('/')
            else:
                return render(request, 'login.html', {'form': form})
    else:
        form = LoginForm()
    return render(request, 'login.html', {'form': form})


def logout_user(request):
    logout(request)
    return redirect('/')


@login_required
def edit_profile(request):
    if request.method == 'POST':
        form = UserUpdateForm(request.POST, instance=request.user)
        profile_form = UserUpdateForm(request.POST, request.FILES, instance=request.user)
        if form.is_valid():
            user_form = form.save()
            custom_form = profile_form.save(False)
            custom_form.user = user_form
            custom_form.save()
            messages.success(request, 'Your profile information was successfully updated!')

            return redirect('edit')
    else:
        form = UserUpdateForm(instance=request.user)
        profile_form = UserUpdateForm(instance=request.user)
        domain_form = UserDomainForm(instance=request.user)
        args = {'form': form, 'profile_form': profile_form, 'domain_form': domain_form}
        # args.update(csrf(request))
        return render(request, 'profile.html', args)


@login_required
def change_password(request):
    if request.method == 'POST':
        form = ChangePasswordForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Important!
            messages.success(request, 'Your password was successfully updated!')
            return redirect('edit')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = ChangePasswordForm(request.user)
    return render(request, 'change_password.html', {
        'form': form
    })


@login_required
def subscriptions(request):
    return render(request, 'subscriptions.html')


@login_required
def request_subscription(request):
    if request.method == 'POST':
        form = SubscriptionRequestForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            tier = data['tier_level']
            if request.user.is_pro and tier == 'pro' or request.user.is_business and tier == 'business':
                return messages.error(request, 'You already have this user tier')
            request = SubscriptionRequest(
                user=request.user,
                tier_level=data['tier_level']
            )
            request.save()
            return redirect('/')
    else:
        form = SubscriptionRequestForm()
    return render(request, 'subscription_request.html', {'form': form})

