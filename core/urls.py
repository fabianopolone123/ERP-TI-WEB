from django.contrib.auth import views as auth_views
from django.urls import path

from .views import (
    ChamadosView,
    CustomLoginView,
    DashboardView,
    UsersListView,
    move_ticket,
    ticket_detail,
    ticket_reclassify,
    ticket_message,
    ticket_update,
    email_templates_update,
    whatsapp_templates_update,
    whatsapp_settings_update,
    ticket_reopen,
)

urlpatterns = [
    path('login/', CustomLoginView.as_view(), name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('usuarios/', UsersListView.as_view(), name='usuarios'),
    path('chamados/', ChamadosView.as_view(), name='chamados'),
    path('chamados/mover/', move_ticket, name='chamados_mover'),
    path('chamados/detalhe/<int:ticket_id>/', ticket_detail, name='chamados_detalhe'),
    path('chamados/reclassificar/', ticket_reclassify, name='chamados_reclassificar'),
    path('chamados/mensagem/', ticket_message, name='chamados_mensagem'),
    path('chamados/atualizar/', ticket_update, name='chamados_atualizar'),
    path('chamados/email-templates/', email_templates_update, name='chamados_email_templates'),
    path('chamados/whatsapp-templates/', whatsapp_templates_update, name='chamados_whatsapp_templates'),
    path('chamados/whatsapp-settings/', whatsapp_settings_update, name='chamados_whatsapp_settings'),
    path('chamados/reabrir/', ticket_reopen, name='chamados_reabrir'),
    path('', DashboardView.as_view(), name='dashboard'),
]
