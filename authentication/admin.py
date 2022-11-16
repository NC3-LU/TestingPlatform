from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import Subscription
from .models import SubscriptionRequest
from .models import User


class UserAdmin(BaseUserAdmin):
    fieldsets = (
        *BaseUserAdmin.fieldsets,
        (
            "Company Data",
            {"fields": ("company_name", "address", "post_code", "city", "vat_number")},
        ),
        ("Subscriptions", {"fields": ("tier_level",)}),
    )
    list_display = ("username", "email", "company_name", "tier_level")


class SubscriptionAdmin(admin.ModelAdmin):
    list_display = ["__str__", "tier_level", "date_activated"]


class SubscriptionRequestAdmin(admin.ModelAdmin):

    actions = [
        "validate_status",
        "decline_status",
        "pending_status",
    ]

    def validate_status(self, request, queryset):
        for sub_request in queryset:
            user = sub_request.user
            user.tier_level = sub_request.tier_level
            try:
                sub = Subscription.objects.get(user=user)
                sub.tier_level = sub_request.tier_level
            except Subscription.DoesNotExist:
                sub = Subscription(user=user, tier_level=user.tier_level)
            user.save()
            sub.save()
            sub_request.delete()

    def decline_status(self, request, queryset):
        queryset.update(status=False)

    def pending_status(self, request, queryset):
        queryset.update(status=None)

    decline_status.short_description = "Decline"
    validate_status.short_description = "Validate"
    pending_status.short_description = "Set to pending"

    list_display = ("__str__", "tier_level", "status")


admin.site.register(User, UserAdmin)
admin.site.register(SubscriptionRequest, SubscriptionRequestAdmin)
admin.site.register(Subscription, SubscriptionAdmin)
