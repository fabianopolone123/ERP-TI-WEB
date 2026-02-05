from django.contrib.auth import views as auth_views
from django.urls import path

from .views import ChamadosView, DashboardView, UsersListView, move_ticket

urlpatterns = [
    path('login/', auth_views.LoginView.as_view(template_name='auth/login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('usuarios/', UsersListView.as_view(), name='usuarios'),
    path('chamados/', ChamadosView.as_view(), name='chamados'),
    path('chamados/mover/', move_ticket, name='chamados_mover'),
    path('', DashboardView.as_view(), name='dashboard'),
]
