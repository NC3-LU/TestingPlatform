from django.urls import path
from . import views

urlpatterns = [
    path('signup/', views.signup, name='signup'),
    path('login/', views.login_user, name='login'),
    path('logout/', views.logout_user, name='logout'),
    path('settings/', views.edit_profile, name='edit'),
    path('change-password/', views.change_password, name='change_password')

]
