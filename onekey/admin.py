from django.contrib import admin, messages

from .helpers import api_login, client_upload_firmware, get_default_product_group
from .models import FirmwareAnalysisRequest

# Register your models here.


@admin.register(FirmwareAnalysisRequest)
class FirmwareAnalysisRequestAdmin(admin.ModelAdmin):
    actions = [
        "validate_status",
        "decline_status",
        "pending_status",
    ]

    @admin.action(description="Validate")
    def validate_status(self, request, queryset):
        for analysis_request in queryset:
            if not analysis_request.firmware_uuid:
                client = api_login()
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

    @admin.action(description="Decline")
    def decline_status(self, request, queryset):
        queryset.update(status=False)

    @admin.action(description="Set to pending")
    def pending_status(self, request, queryset):
        queryset.update(status=None)
