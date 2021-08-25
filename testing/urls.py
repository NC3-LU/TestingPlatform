from django.urls import path
from . import views

urlpatterns = [
    path('pingtest/', views.ping_test, name='ping_test'),
]