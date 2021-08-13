from django.shortcuts import render
from django.http import HttpResponse


# Create your views here.
def index(request):
    # Render the HTML template signup.html
    return render(request, 'index.html')
