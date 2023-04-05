from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="automation"),
    path("auto-ping/", views.schedule_ping, name="schedule_ping"),
    path("auto-ping/<domain>/remove", views.remove_ping, name="remove_ping"),
    # path('auto-whois/', views.schedule_whois, name='schedule_whois'),
    # path('auto-whois/<domain>', views.display_whois_report, name='display_ping_report'),
    path("auto-http/", views.schedule_http, name="schedule_http"),
    path("auto-http/<domain>", views.display_http_report, name="display_http_report"),
    path(
        "auto-http/<domain>/remove", views.remove_http_report, name="remove_http_report"
    ),
]
