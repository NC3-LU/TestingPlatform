from django.urls import path
from . import views


urlpatterns = [
   path('', views.index, name='iot_index'),
   path('tos/', views.read_tos, name='iot_tos'),
   path('request/', views.analysis_request, name='analysis_request'),
   path('<firmware_uuid>/download/', views.download_report, name='download_report')
]
