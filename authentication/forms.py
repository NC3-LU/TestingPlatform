from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, PasswordChangeForm, PasswordResetForm

from .models import User, SubscriptionRequest
from testing.models import UserDomain, MailDomain


class SignUpForm(UserCreationForm):
    email = forms.EmailField(max_length=254, help_text='Contact email')
    company_name = forms.CharField(max_length=30)
    address = forms.CharField(max_length=200)
    post_code = forms.CharField(max_length=200)
    city = forms.CharField(max_length=200)
    vat_number = forms.CharField(max_length=30, required=False,
                                 help_text='Needed for subscription, otherwise optional')

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


class UserDomainForm(forms.ModelForm):

    class Meta:
        model = UserDomain
        fields = ['domain']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'


class MailDomainForm(forms.ModelForm):

    class Meta:
        model = MailDomain
        fields = ['domain']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'
