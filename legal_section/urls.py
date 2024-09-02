from django.urls import path

from . import views

urlpatterns = [
    path("privacy/", views.privacy, name="privacy"),
    path("terms-conditions/", views.tos, name="tos"),
]
