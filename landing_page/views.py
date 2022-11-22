import sys

from django.http import JsonResponse
from django.shortcuts import render

from authentication.models import User
from landing_page.tools import check_mail
from testing_platform.context_processors import get_version


def index(request):
    return render(request, "index.html")


def about(request):
    return render(request, "about.html")


def health(request):
    result = {
        "python_version": "{}.{}.{}".format(*sys.version_info[:3]),
        "database": {},
    }
    result.update(get_version(request))
    result["database"]["SQL"] = True if User.objects.all().count() >= 1 else False
    result["database"]["kvrocks"] = False
    result["email"] = check_mail()
    return JsonResponse(result, safe=False)
