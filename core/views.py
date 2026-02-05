from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import JsonResponse
from django.urls import reverse
from django.views.decorators.http import require_POST
from django.views.generic import TemplateView

from .ldap_importer import import_ad_users
from .models import ERPUser, Ticket

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
    {'slug': 'emprestimos', 'label': 'Empréstimos', 'url_name': None},
    {'slug': 'chamados', 'label': 'Chamados', 'url_name': 'chamados'},
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


def is_ti_user(request) -> bool:
    username = getattr(request.user, 'username', '')
    if not username:
        return False
    user = ERPUser.objects.filter(username__iexact=username).first()
    if not user:
        return False
    return (user.department or '').strip().upper() == 'TI'


class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = 'core/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        is_ti = is_ti_user(self.request)
        active_slug = ERP_MODULES[0]['slug'] if is_ti and ERP_MODULES else None
        context['is_ti_group'] = is_ti
        context['modules'] = build_modules(active_slug) if is_ti else []
        return context


class UsersListView(LoginRequiredMixin, TemplateView):
    template_name = 'core/users_list.html'

    def post(self, request, *args, **kwargs):
        is_ti = is_ti_user(request)
        if not is_ti:
            messages.error(request, 'Apenas usuários do departamento TI podem importar do AD.')
            return self.get(request, *args, **kwargs)

        try:
            created, updated = import_ad_users()
            messages.success(request, f'Importação concluída: {created} novos, {updated} atualizados.')
        except Exception as exc:
            messages.error(request, f'Falha ao importar do AD: {exc}')
        return self.get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        is_ti = is_ti_user(self.request)
        context['is_ti_group'] = is_ti
        context['modules'] = build_modules('usuarios') if is_ti else []
        show_inactive = self.request.GET.get('show_inactive') == '1'
        queryset = ERPUser.objects.all()
        if not show_inactive:
            queryset = queryset.filter(is_active=True)
        context['show_inactive'] = show_inactive
        context['users'] = queryset.order_by('full_name')
        return context


class ChamadosView(LoginRequiredMixin, TemplateView):
    template_name = 'core/chamados.html'

    def post(self, request, *args, **kwargs):
        title = request.POST.get('title', '').strip()
        description = request.POST.get('description', '').strip()
        ticket_type = request.POST.get('ticket_type', '').strip()
        urgency = request.POST.get('urgency', '').strip()
        attachment = request.FILES.get('attachment')

        if not title or not description or not ticket_type or not urgency:
            messages.error(request, 'Preencha título, descrição, tipo e urgência.')
            return self.get(request, *args, **kwargs)

        Ticket.objects.create(
            title=title,
            description=description,
            ticket_type=ticket_type,
            urgency=urgency,
            status=Ticket.Status.PENDENTE,
            created_by=request.user,
            attachment=attachment,
        )
        messages.success(request, 'Chamado aberto com sucesso.')
        return self.get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        is_ti = is_ti_user(self.request)
        context['is_ti_group'] = is_ti
        context['modules'] = build_modules('chamados') if is_ti else []
        context['ti_users'] = ERPUser.objects.filter(department__iexact='TI', is_active=True).order_by('full_name')
        context['pending_tickets'] = Ticket.objects.filter(status=Ticket.Status.PENDENTE).order_by('-created_at')
        context['closed_tickets'] = Ticket.objects.filter(status=Ticket.Status.FECHADO).order_by('-created_at')
        context['in_progress_tickets'] = Ticket.objects.filter(status=Ticket.Status.EM_ATENDIMENTO)
        return context


@require_POST
def move_ticket(request):
    if not is_ti_user(request):
        return JsonResponse({'ok': False, 'error': 'forbidden'}, status=403)

    ticket_id = request.POST.get('ticket_id')
    target = request.POST.get('target')
    if not ticket_id or not target:
        return JsonResponse({'ok': False, 'error': 'invalid'}, status=400)

    ticket = Ticket.objects.filter(id=ticket_id).first()
    if not ticket:
        return JsonResponse({'ok': False, 'error': 'not_found'}, status=404)

    if target == 'pendente':
        ticket.status = Ticket.Status.PENDENTE
        ticket.assigned_to = None
    elif target == 'fechado':
        ticket.status = Ticket.Status.FECHADO
    elif target.startswith('user_'):
        user_id = target.replace('user_', '')
        assignee = ERPUser.objects.filter(id=user_id).first()
        if not assignee:
            return JsonResponse({'ok': False, 'error': 'user_not_found'}, status=404)
        ticket.status = Ticket.Status.EM_ATENDIMENTO
        ticket.assigned_to = assignee
    else:
        return JsonResponse({'ok': False, 'error': 'invalid_target'}, status=400)

    ticket.save()
    return JsonResponse({'ok': True})
