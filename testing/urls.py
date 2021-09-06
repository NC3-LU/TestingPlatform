from django.urls import path
from . import views


urlpatterns = [
    path('', views.test_landing, name='testing'),
    path('pingtest/', views.ping_test, name='ping_test'),
]
