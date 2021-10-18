from django.shortcuts import render, redirect
from .forms import ContactForm
from django.core.mail import send_mail, BadHeaderError
from django.http import HttpResponse
from django.conf import settings
from django.contrib.auth.decorators import login_required


@login_required
def contact(request):
    if request.method == 'POST':
        form = ContactForm(request.POST)
        if form.is_valid():
            subject = "Testing Platform Contact Mail"
            body = {
                'company_name': form.cleaned_data['company_name'],
                'email': form.cleaned_data['email_address'],
                'message': form.cleaned_data['message'],
            }
            message = '\n'.join(body.values())

            try:
                send_mail(subject, message, 'mailagent@securitymadein.lu', ['peer.heinen@securitymadein.lu'])
            except BadHeaderError:
                return HttpResponse('Invalid header found')
            return render(request, 'success.html')
    else:
        form = ContactForm()
    return render(request, 'contact.html', {'form': form})
