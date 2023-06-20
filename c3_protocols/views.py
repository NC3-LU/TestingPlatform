from django.contrib.auth.decorators import login_required
from django.shortcuts import render


@login_required
def c3_protocols(request):
    return render(request, "c3_protocols.html")
