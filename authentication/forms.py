from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, PasswordChangeForm, PasswordResetForm
from django.core.exceptions import ValidationError

from .models import User, SubscriptionRequest
from testing.models import UserDomain, MailDomain

import re


class SignUpForm(UserCreationForm):
    email = forms.EmailField(max_length=254, help_text='Contact email')
    company_name = forms.CharField(max_length=30)
    address = forms.CharField(max_length=200)
    post_code = forms.CharField(max_length=200)
    city = forms.CharField(max_length=200)
    vat_number = forms.CharField(max_length=30, help_text='Needed for subscription. Format: LU12345678')

    class Meta(UserCreationForm.Meta):
        model = User
        fields = ('username', 'email', 'password1', 'password2', 'company_name', 'address', 'post_code', 'city',
                  'vat_number')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'


class LoginForm(AuthenticationForm):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'


class UserUpdateForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['username', 'email', 'company_name', 'address', 'post_code', 'city', 'vat_number']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'


class ChangePasswordForm(PasswordChangeForm):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'


class ResetPasswordEmail(PasswordResetForm):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'


class SubscriptionRequestForm(forms.ModelForm):
    class Meta:
        model = SubscriptionRequest
        fields = ['tier_level']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'


class DomainForm(forms.ModelForm):
    def clean_domain(self):
        domain = self.cleaned_data['domain']
        domain_regex = re.compile(r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$')
        result = domain_regex.match(domain)
        if not result:
            raise ValidationError('Please enter a valid domain format, i.e: domainname.com')
        if '\\u' in domain:
            raise ValidationError('Unknown character encoding, please retry.')
        return domain

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'


class UserDomainForm(DomainForm):

    class Meta:
        model = UserDomain
        fields = ['domain']


class MailDomainForm(DomainForm):

    class Meta:
        model = MailDomain
        fields = ['domain']
