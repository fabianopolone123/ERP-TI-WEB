from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse
from django.views.generic import TemplateView

from .models import ERPUser

ERP_MODULES = [
    {'slug': 'usuarios', 'label': 'Usuários', 'url_name': 'usuarios'},
    {'slug': 'acessos', 'label': 'Acessos', 'url_name': None},
    {'slug': 'equipamentos', 'label': 'Equipamentos', 'url_name': None},
    {'slug': 'ips', 'label': 'IPs', 'url_name': None},
    {'slug': 'emails', 'label': 'Emails', 'url_name': None},
    {'slug': 'ramais', 'label': 'Ramais', 'url_name': None},
    {'slug': 'softwares', 'label': 'Softwares', 'url_name': None},
    {'slug': 'insumos', 'label': 'Insumos', 'url_name': None},
    {'slug': 'requisicoes', 'label': 'Requisições', 'url_name': None},
    {'slug': 'emprestimos', 'label': 'Emprestimos', 'url_name': None},
    {'slug': 'chamados', 'label': 'Chamados', 'url_name': None},
]


def build_modules(active_slug: str | None) -> list[dict[str, str | bool]]:
    modules = []
    for module in ERP_MODULES:
        url_name = module.get('url_name')
        url = reverse(url_name) if url_name else '#'
        modules.append(
            {
                'slug': module['slug'],
                'label': module['label'],
                'url': url,
                'active': module['slug'] == active_slug,
            }
        )
    return modules


class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = 'core/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        is_ti_group = self.request.user.groups.filter(name='TI').exists()
        active_slug = ERP_MODULES[0]['slug'] if is_ti_group and ERP_MODULES else None
        context['is_ti_group'] = is_ti_group
        context['modules'] = build_modules(active_slug) if is_ti_group else []
        return context


class UsersListView(LoginRequiredMixin, TemplateView):
    template_name = 'core/users_list.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        is_ti_group = self.request.user.groups.filter(name='TI').exists()
        context['is_ti_group'] = is_ti_group
        context['modules'] = build_modules('usuarios') if is_ti_group else []
        context['users'] = ERPUser.objects.select_related('group').all().order_by('full_name')
        return context
