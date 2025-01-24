from django.urls import path

from . import views

urlpatterns = [
    path("web-test/", views.check_website_security, name="web_test"),
    path("email-test/", views.email_test, name="email_test"),
    path("file-test/", views.file_test, name="file_test"),
    path("service-test/", views.web_server_test, name="service-test"),
    path("url-test/", views.url_test, name="url-test"),
    path("spf-generator/", views.spf_generator, name="spf-generator"),
    path("dmarc-generator/", views.dmarc_generator, name="dmarc-generator"),
    path("email-policy-generator/", views.record_generator, name="email_policy_generator"),
    path("<test>/export/<site>", views.pdf_from_template, name="pdf_from_template"),
    path('uri-report/<uuid:endpoint_uuid>/', views.csp_report_endpoint,
         name='csp_report_endpoint'),
    path('csp/manage/', views.manage_csp_endpoints, name='manage_csp_endpoints'),
    path('csp/create/', views.create_csp_endpoint, name='create_csp_endpoint'),
    path('csp/reports/<str:endpoint_uuid>/', views.view_csp_reports,
         name='view_csp_reports'),

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
