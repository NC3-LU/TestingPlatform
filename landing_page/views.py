from django.shortcuts import render


def index(request):
    return render(request, "index.html")


def ldih(request, ldih_uuid):
    return render(request, "ldih_landing.html", context={"ldih_uuid": ldih_uuid})
