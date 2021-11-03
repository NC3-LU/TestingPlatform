from django.urls import path
from . import views
from django.contrib.auth import views as auth_views


urlpatterns = [
    path('signup/', views.signup, name='signup'),
    path('login/', views.login_user, name='login'),
    path('logout/', views.logout_user, name='logout'),
    path('settings/', views.edit_profile, name='edit'),
    path('account/change-password/', views.change_password, name='change_password'),
    path('account/password-reset/',
         auth_views.PasswordResetView.as_view(
             template_name='password_reset.html',
             subject_template_name='password_reset_subject.txt',
             email_template_name='password_reset_email.html',
             success_url='/login/'
         ),
         name='password_reset'),
    path('account/password-reset/done/',
         auth_views.PasswordResetDoneView.as_view(
             template_name='password_reset_done.html'
         ),
         name='password_reset_done'),
    path('account/password-reset-confirm/<uidb64>/<token>/',
         auth_views.PasswordResetConfirmView.as_view(
             template_name='password_reset_confirm.html'
         ),
         name='password_reset_confirm'),
    path('account/password-reset-complete/',
         auth_views.PasswordResetCompleteView.as_view(
             template_name='password_reset_complete.html'
         ),
         name='password_reset_complete'),

    path('subscriptions/', views.subscriptions, name='subscriptions'),
    path('subscriptions/request/', views.request_subscription, name='request_subscription'),

    path('settings/domains/add/', views.add_domain, name='add_domain'),
    path('settings/domains/<domain>/remove/', views.remove_domain, name='remove_domain'),

    path('settings/mail-domains/add/', views.add_mail_domain, name='add_mail_domain'),
    path('settings/mail-domains/<domain>/remove/', views.remove_mail_domain, name='remove_mail_domain')
]
