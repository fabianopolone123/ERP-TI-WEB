from django.contrib import admin

from .models import ERPUser, Ticket, TicketMessage


@admin.register(ERPUser)
class ERPUserAdmin(admin.ModelAdmin):
    list_display = (
        'full_name',
        'department',
        'phone',
        'mobile',
        'email',
        'extension',
        'username',
        'is_active',
    )
    list_filter = ('department', 'is_active')
    search_fields = ('full_name', 'department', 'username', 'email')


@admin.register(Ticket)
class TicketAdmin(admin.ModelAdmin):
    list_display = ('title', 'ticket_type', 'urgency', 'status', 'assigned_to', 'created_at')
    list_filter = ('ticket_type', 'urgency', 'status')
    search_fields = ('title', 'description')


@admin.register(TicketMessage)
class TicketMessageAdmin(admin.ModelAdmin):
    list_display = ('ticket', 'created_by', 'is_internal', 'created_at')
    list_filter = ('is_internal',)
    search_fields = ('message',)
