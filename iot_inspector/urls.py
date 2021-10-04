from django.urls import path
from . import views


urlpatterns = [
   path('', views.index, name='index'),
   path('request/', views.analysis_request, name='analysis_request')
]
