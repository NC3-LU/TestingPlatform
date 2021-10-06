from django.urls import path
from . import views


urlpatterns = [
   path('', views.index, name='index'),
   path('request/', views.schedule_test, name='analysis_request'),
]
