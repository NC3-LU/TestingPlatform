from django.contrib.auth.decorators import login_required
from django.shortcuts import render


# Create your views here.

# @login_required
def securityheaders(request):
    # Render the HTML template signup.html
    return render(request, 'security_headers.html')
