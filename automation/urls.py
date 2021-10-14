from django.urls import path
from . import views


urlpatterns = [
   path('', views.index, name='automation'),
   path('ping/', views.schedule_ping, name='schedule_ping'),
   path('http/', views.schedule_http, name='schedule_http'),
   path('http/<task_id>', views.display_http_report, name='display_http_report'),
]
