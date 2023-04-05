from django.contrib import admin

from .models import HttpAutomatedTest, PingAutomatedTest

# Register your models here.
admin.site.register(PingAutomatedTest)
admin.site.register(HttpAutomatedTest)
