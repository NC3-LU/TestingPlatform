from django.contrib import admin
from django.contrib.admin.decorators import display

from testing.models import (
    DMARCRecord,
    DMARCReport,
    MailDomain,
    TlsScanHistory,
    UserDomain,
)

# Register your models here.


@admin.register(MailDomain, UserDomain)
class DomainAdmin(admin.ModelAdmin):
    list_display = ["__str__", "get_company_name", "get_username"]

    @display(description="Company")
    def get_company_name(self, obj):
        return obj.user.company_name

    @display(description="User")
    def get_username(self, obj):
        return obj.user.username


admin.site.register(DMARCRecord)
admin.site.register(DMARCReport)
admin.site.register(TlsScanHistory)
