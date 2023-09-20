from django.urls import path
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

from .views import (
    AutomatedScheduledApiView,
    AutomatedSuccessApiView,
    TlsScanHistoryApiView,
)

urlpatterns = [
    path("schema/", SpectacularAPIView.as_view(), name="testing"),
    path(
        "swagger-ui/",
        SpectacularSwaggerView.as_view(url_name="testing"),
        name="swagger-ui",
    ),
    path("redoc/", SpectacularRedocView.as_view(url_name="testing"), name="redoc"),
    path("TlsScanHistory/", TlsScanHistoryApiView.as_view()),
    path("AutomatedTasks/Success/", AutomatedSuccessApiView.as_view()),
    path("AutomatedTasks/Scheduled/", AutomatedScheduledApiView.as_view()),
]
