from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView

ERP_MODULES = [
    'Usuarios',
    'Acessos',
    'Equipamentos',
    'IPs',
    'Emails',
    'Ramais',
    'Softwares',
    'Insumos',
    'Requisicoes',
    'Emprestimos',
    'Chamados',
]


class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = 'core/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        is_ti_group = self.request.user.groups.filter(name='TI').exists()
        context['is_ti_group'] = is_ti_group
        context['modules'] = ERP_MODULES if is_ti_group else []
        return context
