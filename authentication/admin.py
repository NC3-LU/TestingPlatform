from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import User


class UserAdmin(BaseUserAdmin):
    fieldsets = (
        *BaseUserAdmin.fieldsets,
        (
            "Company Data",
            {"fields": ("company_name", "address", "post_code", "city", "vat_number")},
        ),
    )
    list_display = ("username", "email", "company_name")


admin.site.register(User, UserAdmin)
