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
    path('', DashboardView.as_view(), name='dashboard'),
]
