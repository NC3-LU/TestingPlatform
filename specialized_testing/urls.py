from django.urls import include
from django.urls import path

from . import views


urlpatterns = [
    path("", views.index, name="spec_test"),
    path("iot-inspector/", include("iot_inspector.urls")),
]
