from django.shortcuts import render
from django.contrib.auth.decorators import login_required


@login_required
def c3_protocols(request):
    return render(request, 'c3_protocols.html')
