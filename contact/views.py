from django.core.mail import BadHeaderError, send_mail
from django.http import HttpResponse
from django.shortcuts import render

from .forms import ContactForm


def contact(request):
    if request.method == "POST":
        form = ContactForm(request.POST)
        if form.is_valid():
            subject = "Testing Platform Contact Mail"
            body = {
                "company_name": form.cleaned_data["company_name"],
                "email": form.cleaned_data["email_address"],
                "message": form.cleaned_data["message"],
            }
            message = "\n".join(body.values())

            try:
                send_mail(
                    subject,
                    message,
                    from_email=form.cleaned_data["email_address"],
                    recipient_list=["contact.testing@c3.lu"],
                )
            except BadHeaderError:
                return HttpResponse("Invalid header found")
            return render(request, "success.html")
    else:
        form = ContactForm()
    return render(request, "contact.html", {"form": form})
