from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib import messages

from decouple import config

from .helpers import api_login, api_add_user, client_login, client_upload_firmware, get_default_product_group, \
    client_get_report_link, client_generate_report, api_get_report
from .models import AnalysisRequest, IOTUser

from testing_platform import settings


class AnalysisRequestAdmin(admin.ModelAdmin):

    actions = ['validate_status', 'decline_status', 'pending_status', ]

    def validate_status(self, request, queryset):
        for analysis_request in queryset:
            iot_user = analysis_request.iot_user
            if iot_user.activated and analysis_request.status not in (True, False):
                if not analysis_request.firmware_uuid:
                    client = client_login(iot_user)
                    default_product_group = get_default_product_group(client)
                    firmware = client_upload_firmware(client, analysis_request, default_product_group)
                    firmware_uuid = firmware['id']
                    analysis_request.firmware_uuid = firmware_uuid
                    report = client_generate_report(client, firmware_uuid)
                    report_uuid = report['id']
                    analysis_request.report_uuid = report_uuid
                    status, link = None, None
                    while status != 'FINISHED':
                        (status, link) = client_get_report_link(client, report_uuid)
                        print(status)
                    analysis_request.report_link = link
                    analysis_request.status = True
                    analysis_request.save()
                else:
                    messages.error(request, 'This request was already made.')
            else:
                messages.error(request,
                               'This user was not created on the IoT Inspector platform, please activate it first.')

    def decline_status(self, request, queryset):
        queryset.update(status=False)

    def pending_status(self, request, queryset):
        queryset.update(status=None)

    decline_status.short_description = "Decline"
    validate_status.short_description = "Validate"
    pending_status.short_description = "Set to pending"

    list_display = ['__str__', 'status', 'iot_user']


class IOTUserAdmin(admin.ModelAdmin):

    readonly_fields = ('password',)
    actions = ['activate_iot']
    list_display = ['__str__', 'activated']

    def activate_iot(self, request, queryset):
        login = api_login(settings.IOT_API_EMAIL, settings.IOT_API_PASSWORD)
        for iotuser in queryset:
            token = login['tenant_token']
            response = api_add_user(iotuser, token)
            if response.status_code not in (200, 204):
                messages.error(request, f'{response.json()["errors"][0]["detail"]}')
            else:
                queryset.update(activated=True)


# Register your models here.
admin.site.register(AnalysisRequest, AnalysisRequestAdmin)
admin.site.register(IOTUser, IOTUserAdmin)
