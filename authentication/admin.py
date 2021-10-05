from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User


class UserAdmin(BaseUserAdmin):
    readonly_fields = ('vat_number', 'first_name', 'last_name', 'username')
    fieldsets = (*BaseUserAdmin.fieldsets, ('Commercial Data', {'fields': ('company_name', 'vat_number')}))


admin.site.register(User, UserAdmin)
