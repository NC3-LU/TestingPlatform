from django.shortcuts import render
from django.http import HttpResponse
from authentication.models import User


# Create your views here.
def index(request):
    # Render the HTML template signup.html
    return render(request, 'index.html')


def healthz(request):
    count = User.objects.all().count()
    if count >= 1:
        return HttpResponse(status=200, content='OK')
    else:
        return HttpResponse(status=503, content='NOK')
