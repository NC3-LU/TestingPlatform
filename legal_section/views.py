from django.shortcuts import render


def legal(request):
    return render(request, "privacy.html")


def privacy(request):
    return render(request, "privacy.html")


def tos(request):
    return render(request, "tos.html")
