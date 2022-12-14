from django.urls import include
from django.urls import path

from . import views

urlpatterns = [
    path("", views.test_landing, name="test_index"),
    # path('whois-lookup/', views.ping_test, name='ping_test'),
    path("http-test/", views.http_test, name="http_test"),
    path("spf-generator/", views.spf_generator, name="spf-generator"),
    path("dmarc-generator/", views.dmarc_generator, name="dmarc-generator"),
    path("dmarc-reporter/", views.dmarc_reporter, name="dmarc-reporter"),
    path(
        "dmarc-reporter/<str:domain>/<mailfrom>/<timestamp>/",
        views.dmarc_shower,
        name="dmarc-shower",
    ),
    path(
        "dmarc-reporter/<str:domain>/<mailfrom>/<timestamp>/download/",
        views.dmarc_dl,
        name="dmarc-dl",
    ),
    # path('dmarc-reporter/upload/', views.dmarc_upload, name='dmarc-uploader'),
    path("automation/", include("automation.urls")),
]
