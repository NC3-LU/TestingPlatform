from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate, update_session_auth_hash
from django.http import HttpResponseRedirect

from .forms import SignUpForm, LoginForm, UserUpdateForm, ChangePasswordForm


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

            return redirect('index')
    else:
        form = SignUpForm()
    return render(request, 'signup.html', {'form': form})


def login_user(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
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
    return redirect('index')


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
        args = {'form': form, 'profile_form': profile_form}
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

