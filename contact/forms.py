from django import forms

class ContactForm(forms.Form):
    first_name = forms.CharField(max_length=50)
    last_name = forms.CharField(max_length=50)
    company_name = forms.CharField(max_length=64)
    email_address = forms.EmailField(max_length=128)
    message = forms.CharField(widget = forms.Textarea, max_length= 2048)