from django.urls import path

from . import views

urlpatterns = [
    path("http-test/", views.http_test, name="http_test"),
    path("email-test/", views.email_test, name="email_test"),
    path("file-test/", views.file_test, name="file_test"),
    path("infra-test/", views.web_server_test, name="infra-test"),
    path("spf-generator/", views.spf_generator, name="spf-generator"),
    path("dmarc-generator/", views.dmarc_generator, name="dmarc-generator"),
    path("email-policy-generator/", views.record_generator, name="email_policy_generator"),

    # path('whois-lookup/', views.ping_test, name='ping_test'),

    # path("web-test/", views.web_test, name="web_test"),

    # path("ipv6-test/", views.ipv6_test, name="ipv6_test"),


    # path("dmarc-reporter/", views.dmarc_reporter, name="dmarc-reporter"),
    # path(
    #     "dmarc-reporter/<str:domain>/<mailfrom>/<timestamp>/",
    #    views.dmarc_shower,
    #    name="dmarc-shower",
    # ),
    # path(
    #   "dmarc-reporter/<str:domain>/<mailfrom>/<timestamp>/download/",
    #   views.dmarc_dl,
    #   name="dmarc-dl",
    # ),
    # path('dmarc-reporter/upload/', views.dmarc_upload, name='dmarc-uploader'),
    # path("automation/", include("automation.urls")),
]
