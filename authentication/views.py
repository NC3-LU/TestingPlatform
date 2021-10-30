from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate, update_session_auth_hash
from django.http import HttpResponseRedirect

from .forms import SignUpForm, LoginForm, UserUpdateForm, ChangePasswordForm, SubscriptionRequestForm, UserDomainForm, \
    MailDomainForm
from .models import SubscriptionRequest, Subscription
from testing.models import UserDomain, MailDomain
from iot_inspector.models import IOTUser
import socket


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

    user_domains = UserDomain.objects.filter(user=request.user.id)
    mail_domains = MailDomain.objects.filter(user=request.user.id)
    try:
        subscription = Subscription.objects.get(user=request.user.id)
    except Subscription.DoesNotExist:
        subscription = None
    domain_list, mail_domain_list = [], []
    for domain in user_domains:
        domain_list.append(domain)
    for domain in mail_domains:
        mail_domain_list.append(domain)

    context = {'form': form, 'domain_list': user_domains, 'mail_domain_list': mail_domain_list,
               'subscription': subscription}
    return render(request, 'profile.html', context=context)


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
    return render(request, 'sub_presentation.html')


@login_required
def request_subscription(request):
    if request.method == 'POST':
        form = SubscriptionRequestForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            tier = data['tier_level']
            if request.user.tier_level == tier:
                messages.error(request, 'You already have this user tier')
                return render(request, 'subscription_request.html', {'form': form})
            sub_request = SubscriptionRequest(
                user=request.user,
                tier_level=data['tier_level']
            )
            sub_request.save()
            messages.success(request, 'Your subscription request has been sent successfully, you will receive an email '
                                      'with your pricing offer in the next few days')
            return redirect('edit')
    else:
        form = SubscriptionRequestForm()
    return render(request, 'subscription_request.html', {'form': form})


@login_required
def add_domain(request):
    user = request.user
    domains = user.userdomain_set.all()
    if user.tier_level == 0:
        messages.error(request, 'You must have at least a PRO tier subscription if you wish to register a domain')
        return redirect('edit')
    elif user.tier_level == 1 and len(domains) == 1:
        messages.error(request, 'You must have at least a BUSINESS tier subscription if you wish to register more '
                                'domains')
        return redirect('edit')
    else:
        if request.method == 'POST':
            form = UserDomainForm(request.POST)
            if form.is_valid():
                data = form.cleaned_data
                try:
                    db_domain = UserDomain.objects.get(domain=data['domain'])
                except UserDomain.DoesNotExist:
                    db_domain = None
                if db_domain:
                    if db_domain.user == request.user:
                        messages.error(request,
                                       'You already registered this domain in your company domains.')
                    else:
                        messages.error(request, 'This domain is already registered by someone else. Please contact '
                                                'do@c3.lu if you think someone is monitoring your systems')
                    return redirect('add_domain')
                else:
                    domain = data['domain']
                    try:
                        ip_address = socket.gethostbyname(domain)
                    except socket.gaierror:
                        ip_address = None
                    if ip_address:
                        domain = UserDomain(
                            user=user,
                            domain=domain,
                            ip_address=ip_address
                        )
                        domain.save()
                        messages.success(request, 'Domain added')
                        return redirect('edit')
                    else:
                        messages.error(request, "Your domain name couldn't be resolved, please verify you entered your "
                                                "domain name correctly.")
                        return redirect('add_domain')
        else:
            form = UserDomainForm()
        return render(request, 'add_domain.html', {'form': form, 'type': 'web'})


@login_required
def remove_domain(request, domain):
    user_domain = UserDomain.objects.get(domain=domain)
    if user_domain.user == request.user:
        user_domain.delete()
        messages.success(request, f'Successfully removed {domain} from your managed domains')
        return redirect('edit')
    else:
        messages.error(request, 'This domain is not registered under your account, permission denied')
        return redirect('edit')


@login_required
def add_mail_domain(request):
    user = request.user
    domains = user.maildomain_set.all()
    if request.method == 'POST':
        form = MailDomainForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            domain = MailDomain(
                user=user,
                domain=data['domain']
            )
            domain.save()
            messages.success(request, 'Domain added')
            return redirect('edit')
    else:
        form = MailDomainForm()
    return render(request, 'add_domain.html', {'form': form, 'type': 'mail'})


@login_required
def remove_mail_domain(request, domain):
    mail_domain = MailDomain.objects.get(domain=domain)
    mail_domain.delete()
    messages.success(request, f'Successfully removed {domain} from your managed mail domains')
    return redirect('edit')
