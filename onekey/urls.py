from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="iot_index"),
    path("request/", views.analysis_request, name="analysis_request"),
    path(
        "generate_report/firmware=<firmware_uuid>",
        views.generate_report,
        name="generate_report",
    ),
    path(
        "generate_link/report=<report_uuid>", views.generate_link, name="generate_link"
    ),
    path(
        "download/report=<report_uuid>", views.download_report, name="download_report"
    ),
]
