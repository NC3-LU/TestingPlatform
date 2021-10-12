from django.contrib import admin
from .models import PingAutomatedTest, HttpAutomatedTest


# Register your models here.
admin.site.register(PingAutomatedTest)
admin.site.register(HttpAutomatedTest)
