from django.contrib import admin

from .models import HttpAutomatedTest
from .models import PingAutomatedTest


# Register your models here.
admin.site.register(PingAutomatedTest)
admin.site.register(HttpAutomatedTest)
