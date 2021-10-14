from django.contrib import admin
from django.contrib.admin.decorators import display

# Register your models here.
from testing.models import UserDomain


class UserDomainAdmin(admin.ModelAdmin):
    list_display = ['__str__', 'get_company_name', 'get_username']

    @display(description='Company')
    def get_company_name(self, obj):
        return obj.user.company_name

    @display(description='User')
    def get_username(self, obj):
        return obj.user.username


admin.site.register(UserDomain, UserDomainAdmin)
