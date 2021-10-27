from django.urls import path
from . import views


urlpatterns = [
   path('', views.index, name='automation'),

   path('ping/', views.schedule_ping, name='schedule_ping'),
   path('ping/<domain>', views.display_ping_report, name='display_ping_report'),
   path('ping/<domain>/remove', views.remove_ping, name='remove_ping'),

   path('http/', views.schedule_http, name='schedule_http'),
   path('http/<domain>', views.display_http_report, name='display_http_report'),
   path('http/<domain>/remove', views.remove_http_report, name='remove_http_report'),
]
