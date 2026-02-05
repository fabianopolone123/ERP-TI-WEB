from django.contrib import admin

from .models import ERPUser


@admin.register(ERPUser)
class ERPUserAdmin(admin.ModelAdmin):
    list_display = (
        'full_name',
        'role',
        'department',
        'phone',
        'mobile',
        'email',
        'extension',
        'username',
        'is_active',
    )
    list_filter = ('department', 'is_active')
    search_fields = ('full_name', 'role', 'department', 'username', 'email')
