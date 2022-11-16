from django.urls import path, include
from . import views


urlpatterns = [
    path("", views.index, name="spec_test"),
    path("iot-inspector/", include("iot_inspector.urls")),
]
