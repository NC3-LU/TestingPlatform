from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, SubscriptionRequest


class UserAdmin(BaseUserAdmin):
    readonly_fields = ('vat_number', 'username')
    fieldsets = (*BaseUserAdmin.fieldsets, ('Company Data', {'fields': ('company_name', 'address', 'post_code',
                                                                        'city', 'vat_number')}),
                 ('Subscriptions', {'fields': ('is_pro', 'is_business')}))
    list_display = ('username', 'email', 'company_name', 'is_pro', 'is_business')


class SubscriptionRequestAdmin(admin.ModelAdmin):

    actions = ['validate_status', 'decline_status', 'pending_status', ]

    def validate_status(self, request, queryset):
        for sub_request in queryset:
            user = sub_request.user
            if sub_request.tier_level == 'pro':
                user.is_pro = True
                user.is_business = False
            if sub_request.tier_level == 'business':
                user.is_business = True
                user.is_pro = False
            user.save()
        queryset.update(status=True)

    def decline_status(self, request, queryset):
        queryset.update(status=False)

    def pending_status(self, request, queryset):
        queryset.update(status=None)

    decline_status.short_description = "Decline"
    validate_status.short_description = "Validate"
    pending_status.short_description = "Set to pending"

    list_display = ('__str__', 'tier_level', 'status')


admin.site.register(User, UserAdmin)
admin.site.register(SubscriptionRequest, SubscriptionRequestAdmin)
