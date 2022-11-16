from django.urls import path

from . import views

urlpatterns = [
    path("privacy/", views.privacy, name="privacy"),
    path("tos/", views.tos, name="tos"),
]
