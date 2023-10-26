"""testing_platform URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path

from testing import views
from testing_platform import settings

urlpatterns = [
    path("", include("landing_page.urls")),
    path("", include("authentication.urls")),
    path("", include("legal_section.urls")),
    path("infra-testing/", include("testing.urls")),
    path("c3-protocols/", include("c3_protocols.urls")),
    path("specialized-testing/", include("specialized_testing.urls")),
    path("iot-testing/", include("onekey.urls")),
    path("admin/", admin.site.urls),
    path("contact/", include("contact.urls")),
    path("kb/", include("knowledge_base.urls")),
    path("test/dmarc-reporter/upload/", views.dmarc_upload, name="dmarc-uploader"),
    # API
    path("api-auth/", include("rest_framework.urls")),
    path("api/v1/", include("testing.api.urls")),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
