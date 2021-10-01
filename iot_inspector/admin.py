from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .helpers import iot_api_login, iot_add_user

from .models import AnalysisRequest, IOTUser


class AnalysisRequestAdmin(admin.ModelAdmin):
    actions = ['validate_status', 'decline_status', 'pending_status', ]

    def validate_status(self, request, queryset):
        queryset.update(status=True)
        for analysis_request in queryset:
            iot_user = analysis_request.iot_user

    def decline_status(self, request, queryset):
        queryset.update(status=False)

    def pending_status(self, request, queryset):
        queryset.update(status=None)

    decline_status.short_description = "Decline"
    validate_status.short_description = "Validate"
    pending_status.short_description = "Set to pending"

    list_display = ['__str__', 'status']


class IOTUserAdmin(admin.ModelAdmin):
    readonly_fields = ('password',)
    actions = ['activate_iot']

    def activate_iot(self, request, queryset):
        login = iot_api_login()
        for iotuser in queryset:
            token = login['tenant_token']
            iot_add_user(iotuser, token)
        queryset.update(activated=True)


# Register your models here.
admin.site.register(AnalysisRequest, AnalysisRequestAdmin)
admin.site.register(IOTUser, IOTUserAdmin)
