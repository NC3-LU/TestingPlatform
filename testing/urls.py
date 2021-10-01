from django.urls import path
from . import views

urlpatterns = [
    path('', views.test_landing, name='testing'),
    path('pingtest/', views.ping_test, name='ping_test'),
    path('c3-protocols/', views.c3_protocols, name='c3_protocols'),
]
