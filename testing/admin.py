from django.contrib import admin
from django.contrib.admin.decorators import display

from testing.models import DMARCRecord
from testing.models import DMARCReport
from testing.models import MailDomain
from testing.models import TlsScanHistory
from testing.models import UserDomain

# Register your models here.


class DomainAdmin(admin.ModelAdmin):
    list_display = ["__str__", "get_company_name", "get_username"]

    @display(description="Company")
    def get_company_name(self, obj):
        return obj.user.company_name

    @display(description="User")
    def get_username(self, obj):
        return obj.user.username


admin.site.register(UserDomain, DomainAdmin)
admin.site.register(MailDomain, DomainAdmin)
admin.site.register(DMARCRecord)
admin.site.register(DMARCReport)
admin.site.register(TlsScanHistory)
