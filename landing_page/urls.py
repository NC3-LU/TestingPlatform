from django.urls import path
from django.views.generic.base import TemplateView

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path(
        "robots.txt",
        TemplateView.as_view(template_name="robots.txt", content_type="text/plain"),
    ),
    path(
        "humans.txt",
        TemplateView.as_view(template_name="humans.txt", content_type="text/plain"),
    ),
    path(
        ".well-known/security.txt",
        TemplateView.as_view(template_name="security.txt", content_type="text/plain"),
    ),
    path("ldih/uid=<ldih_uuid>", views.ldih, name='ldih')
]
