from django.contrib import admin

from .models import ERPGroup, ERPUser


@admin.register(ERPGroup)
class ERPGroupAdmin(admin.ModelAdmin):
    search_fields = ('name',)


@admin.register(ERPUser)
class ERPUserAdmin(admin.ModelAdmin):
    list_display = ('full_name', 'role', 'department', 'username', 'is_active', 'group')
    list_filter = ('department', 'group', 'is_active')
    search_fields = ('full_name', 'role', 'department', 'username')
