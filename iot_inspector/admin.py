import logging

from django.contrib import admin, messages

from testing_platform import settings

from .helpers import (
    api_add_user,
    api_login,
    client_generate_report,
    client_get_report_link,
    client_login,
    client_upload_firmware,
    get_default_product_group,
)
from .models import AnalysisRequest, IOTUser

logger = logging.getLogger(__name__)


@admin.register(AnalysisRequest)
class AnalysisRequestAdmin(admin.ModelAdmin):
    actions = [
        "validate_status",
        "decline_status",
        "pending_status",
        "generate_report",
    ]

    @admin.action(description="Validate")
    def validate_status(self, request, queryset):
        for analysis_request in queryset:
            iot_user = analysis_request.iot_user
            if iot_user.activated and analysis_request.status not in (True, False):
                if not analysis_request.firmware_uuid:
                    client = client_login(iot_user)
                    default_product_group = get_default_product_group(client)
                    firmware = client_upload_firmware(
                        client, analysis_request, default_product_group
                    )
                    firmware_uuid = firmware["id"]
                    analysis_request.firmware_uuid = firmware_uuid
                    analysis_request.status = True
                    analysis_request.save()
                else:
                    messages.error(request, "This request was already made.")
            else:
                messages.error(
                    request,
                    "This user was not created on the IoT Inspector platform, please activate it first.",
                )

    @admin.action(description="Decline")
    def decline_status(self, request, queryset):
        queryset.update(status=False)

    @admin.action(description="Set to pending")
    def pending_status(self, request, queryset):
        queryset.update(status=None)

    def generate_report(self, request, queryset):
        for analysis_request in queryset:
            iot_user = analysis_request.iot_user
            if iot_user.activated and analysis_request.status:
                client = client_login(iot_user)
                if analysis_request.report_uuid:
                    status, report_link = client_get_report_link(
                        client, analysis_request.report_uuid
                    )
                    if status == "FAILED":
                        report = client_generate_report(
                            client, analysis_request.firmware_uuid
                        )
                        messages.success(
                            request, "Getting status failed, regenerating."
                        )
                        report_uuid = report["id"]
                        status, report_link = client_get_report_link(
                            client, report_uuid
                        )
                        if status == "FAILED":
                            messages.error(
                                request,
                                "Generation failed, check if the firmware analysis is done.",
                            )
                        else:
                            analysis_request.report_uuid = report_uuid
                            analysis_request.report_link = f"https://smile.iot-inspector.com/api/reports/{report_uuid}/pdf/"
                            analysis_request.save()
                elif not analysis_request.report_uuid:
                    report = client_generate_report(
                        client, analysis_request.firmware_uuid
                    )
                    report_uuid = report["id"]
                    status, report_link = client_get_report_link(client, report_uuid)
                    if status == "FAILED":
                        messages.error(
                            request,
                            "Generation failed, check if the firmware analysis is done.",
                        )
                    else:
                        analysis_request.report_uuid = report_uuid
                        analysis_request.report_link = f"https://smile.iot-inspector.com/api/reports/{report_uuid}/pdf/"
                        analysis_request.save()
                else:
                    messages.error(request, "The report is already generating.")
            else:
                messages.error(
                    request,
                    "The firmware has not been uploaded yet, please validate the request first.",
                )

    list_display = ["__str__", "status", "iot_user"]


@admin.register(IOTUser)
class IOTUserAdmin(admin.ModelAdmin):
    readonly_fields = ("password",)
    actions = ["activate_iot", "get_login"]
    list_display = ["__str__", "activated"]

    def activate_iot(self, request, queryset):
        login = api_login(settings.IOT_API_EMAIL, settings.IOT_API_PASSWORD)
        for iotuser in queryset:
            token = login["tenant_token"]
            response = api_add_user(iotuser, token)
            if response.status_code not in (200, 204):
                messages.error(request, f'{response.json()["errors"][0]["detail"]}')
            else:
                queryset.update(activated=True)

    def get_login(self, request, queryset):
        for iotuser in queryset:
            if not iotuser.login:
                iotuser.login = iotuser.user.email
                iotuser.save()
                messages.success(
                    request, f"Login for {iotuser.user.username} iot inspector added"
                )
            else:
                messages.warning(
                    request, f"User {iotuser.user.username} already has a login."
                )


# Register your models here.
