import sys

from django.http import JsonResponse
from django.shortcuts import render

from authentication.models import User
from testing_platform.context_processors import get_version


def index(request):
    return render(request, "index.html")


def about(request):
    return render(request, "about.html")


def health(request):
    result = {
        "python_version": "{}.{}.{}".format(*sys.version_info[:3]),
    }
    result.update(get_version(request))
    result.update(
        {"pgSQL_data_base": True if User.objects.all().count() >= 1 else False}
    )
    return JsonResponse(result, safe=False)
