from django.urls import path
from . import views

urlpatterns = [
    path('', views.test_landing, name='testing'),
    path('pingtest/', views.ping_test, name='ping_test'),
    path('c3-protocols/', views.c3_protocols, name='c3_protocols'),
    path('check-website/', views.check_website, name='check-website'),
    path('spf-generator/', views.spf_generator, name='spf-generator'),
    path('dmarc-generator/', views.dmarc_generator, name='dmarc-generator'),
    path('dmarc-reporter/', views.dmarc_reporter, name='dmarc-reporter'),
    path('dmarc-reporter/<str:uid>', views.dmarc_shower, name='dmarc-shower'),
]
