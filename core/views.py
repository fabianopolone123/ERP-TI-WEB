import logging
import json
import unicodedata
from textwrap import shorten
from decimal import Decimal, InvalidOperation
from pathlib import Path
from uuid import uuid4
from django.conf import settings
from django.contrib import messages
from django.core.mail import send_mail
from django.db.models import Count, Q
from django.db.models.functions import TruncDate
from django.shortcuts import redirect
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth import get_user_model
from django.http import JsonResponse, FileResponse
from django.urls import reverse
from django.utils.dateparse import parse_date
from django.views.decorators.http import require_GET, require_POST
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import TemplateView
from django.contrib.auth import views as auth_views
from ldap3 import Connection, Server, SUBTREE
from ldap3.utils.conv import escape_filter_chars

from .ldap_importer import import_ad_users
from .chamados_excel import export_attendant_logs_to_excel
from .models import (
    ERPUser,
    Equipment,
    SoftwareInventory,
    Requisition,
    RequisitionQuote,
    AccessFolder,
    AccessMember,
    Ticket,
    TicketMessage,
    TicketTimelineEvent,
    TicketWorkLog,
    WhatsAppTemplate,
    EmailTemplate,
    WhatsAppNotificationSettings,
    WhatsAppOptOut,
)
from .wapi import find_whatsapp_groups_by_name, send_whatsapp_message
from .access_importer import refresh_access_snapshot
from .network_inventory import (
    parse_hosts_text,
    sync_network_inventory,
    format_inventory_run_stamp,
    upsert_inventory_from_payload,
)

logger = logging.getLogger(__name__)
DEFAULT_EMAIL_TEMPLATES = {
    'new_ticket_subject': '[Chamado #{id}] Novo chamado',
    'new_ticket_body': 'Novo chamado #{id}: {title}\n{description}',
    'status_update_subject': '[Chamado #{id}] Status atualizado',
    'status_update_body': 'Status atual: {status}\nResponsável: {responsavel}',
    'new_message_subject': '[Chamado #{id}] Nova mensagem',
    'new_message_body': 'Nova mensagem: {message}',
}
DEFAULT_WA_TEMPLATES = {
    'new_ticket': 'Novo chamado #{id}: {title} | Solicitante: {solicitante} | Tipo: {tipo} | Urgência: {urgencia} | {description}',
    'status_update': 'Chamado #{id} atualizado: {status} | Responsável: {responsavel} | Solicitante: {solicitante}',
    'new_message': 'Nova mensagem no chamado #{id}: {message} | Solicitante: {solicitante}',
}

ERP_MODULES = [
    {'slug': 'usuarios', 'label': 'Usuários', 'url_name': 'usuarios'},
    {'slug': 'acessos', 'label': 'Acessos', 'url_name': 'acessos'},
    {'slug': 'equipamentos', 'label': 'Equipamentos', 'url_name': 'equipamentos'},
    {'slug': 'ips', 'label': 'IPs', 'url_name': None},
    {'slug': 'emails', 'label': 'Emails', 'url_name': None},
    {'slug': 'ramais', 'label': 'Ramais', 'url_name': None},
    {'slug': 'softwares', 'label': 'Softwares', 'url_name': 'softwares'},
    {'slug': 'insumos', 'label': 'Insumos', 'url_name': None},
    {'slug': 'requisicoes', 'label': 'Requisições', 'url_name': 'requisicoes'},
    {'slug': 'emprestimos', 'label': 'Empréstimos', 'url_name': None},
    {'slug': 'chamados', 'label': 'Chamados', 'url_name': 'chamados'},
    {'slug': 'relatorios', 'label': 'Relatórios', 'url_name': 'relatorios'},
]


def _normalize_failure_type(raw_value: str) -> str:
    raw = (raw_value or '').strip().lower()
    if raw in {'n/s', 'ns', 'n-s', 'n/a', 'na', 'n-a'}:
        return Ticket.FailureType.NA
    if raw in {'equipamento', 'hardware'}:
        return Ticket.FailureType.EQUIPAMENTO
    if raw == 'software':
        return Ticket.FailureType.SOFTWARE
    if raw in {'humana', 'falha humana', 'falha_humana'}:
        return Ticket.FailureType.HUMANA
    return raw


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


def _inventory_default_hosts() -> str:
    return (getattr(settings, 'INVENTORY_DEFAULT_HOSTS', '') or '').strip()


def _inventory_agent_token() -> str:
    return (getattr(settings, 'INVENTORY_AGENT_TOKEN', '') or '').strip()


class _SafeDict(dict):
    def __missing__(self, key):
        return ''

def _normalize_text(value: str) -> str:
    raw = (value or '').strip().lower()
    return unicodedata.normalize('NFKD', raw).encode('ascii', 'ignore').decode('ascii')


def _get_user_ad_groups(username: str) -> list[str]:
    server_uri = getattr(settings, 'AD_LDAP_SERVER_URI', '')
    base_dn = getattr(settings, 'AD_LDAP_BASE_DN', '')
    bind_dn = getattr(settings, 'AD_LDAP_BIND_DN', '')
    bind_password = getattr(settings, 'AD_LDAP_BIND_PASSWORD', '')
    if not server_uri or not base_dn or not username:
        return []

    conn = None
    try:
        server = Server(server_uri, get_info=None)
        conn = Connection(server, user=bind_dn, password=bind_password, auto_bind=True)
        safe_username = escape_filter_chars(username)
        user_filter = f'(&(objectCategory=person)(objectClass=user)(sAMAccountName={safe_username}))'
        conn.search(
            search_base=base_dn,
            search_filter=user_filter,
            search_scope=SUBTREE,
            attributes=['memberOf', 'primaryGroupID'],
        )
        if not conn.entries:
            return []
        entry = conn.entries[0]
        member_of = entry.memberOf.values if 'memberOf' in entry else []
        groups: list[str] = []
        for dn in member_of:
            part = str(dn).split(',', 1)[0]
            if part.upper().startswith('CN='):
                groups.append(part[3:])

        # AD can omit the primary group from memberOf, so resolve it via primaryGroupID.
        primary_group_id = entry.primaryGroupID.value if 'primaryGroupID' in entry else None
        if primary_group_id:
            primary_group_id_str = str(primary_group_id)
            # Fallback for well-known RIDs when group lookup does not return.
            if primary_group_id_str == '512':
                groups.append('Admins. do dominio')
            elif primary_group_id_str == '513':
                groups.append('Usuarios do dominio')

            primary_filter = f'(&(objectCategory=group)(primaryGroupToken={primary_group_id}))'
            conn.search(
                search_base=base_dn,
                search_filter=primary_filter,
                search_scope=SUBTREE,
                attributes=['cn'],
            )
            if conn.entries:
                primary_cn = conn.entries[0].cn.value if 'cn' in conn.entries[0] else ''
                if primary_cn:
                    groups.append(str(primary_cn))
        return sorted(set(groups), key=lambda v: v.lower())
    except Exception:
        logger.exception('Falha ao consultar grupos AD do usuario %s', username)
        return []
    finally:
        if conn is not None:
            conn.unbind()


def _get_whatsapp_templates() -> WhatsAppTemplate:
    template, _ = WhatsAppTemplate.objects.get_or_create(
        pk=1,
        defaults=DEFAULT_WA_TEMPLATES,
    )
    return template


def _get_email_templates() -> EmailTemplate:
    template, _ = EmailTemplate.objects.get_or_create(
        pk=1,
        defaults=DEFAULT_EMAIL_TEMPLATES,
    )
    return template


def _get_whatsapp_settings() -> WhatsAppNotificationSettings:
    settings_obj, _ = WhatsAppNotificationSettings.objects.get_or_create(pk=1)
    return settings_obj


def _get_whatsapp_group_jid(settings_obj: WhatsAppNotificationSettings | None = None) -> str:
    if settings_obj is None:
        settings_obj = _get_whatsapp_settings()
    return (settings_obj.group_jid or '').strip() or getattr(settings, "WAPI_DEFAULT_GROUP_JID", "").strip()


def _clean_phone(value: str) -> str:
    digits = ''.join(ch for ch in (value or '') if ch.isdigit())
    if not digits:
        return ''
    if digits.startswith('55') and len(digits) in {12, 13}:
        return digits
    if len(digits) in {10, 11}:
        return f'55{digits}'
    return digits


def _get_attendant_numbers(ticket: Ticket) -> list[str]:
    users = []
    if ticket.assigned_to:
        users.append(ticket.assigned_to)
    users.extend(list(ticket.collaborators.all()))

    if not users:
        return []

    numbers = []
    seen = set()
    for user in users:
        phone = user.mobile or user.phone or ''
        phone = _clean_phone(phone)
        if not phone:
            continue
        if phone in seen:
            continue
        seen.add(phone)
        numbers.append(phone)
    return numbers


def _build_whatsapp_summary(ticket, event_label="Novo chamado", extra_line=None):
    label = (event_label or "").strip().lower()
    title = shorten((ticket.title or "").strip(), width=120, placeholder='...')
    description = shorten((ticket.description or "").strip(), width=160, placeholder='...')
    detail = shorten(((extra_line or "").replace('\n', ' ')).strip(), width=180, placeholder='...')
    requester_name = (getattr(ticket.created_by, 'get_full_name', lambda: '')() or getattr(ticket.created_by, 'username', '') or '').strip()
    requester_username = (getattr(ticket.created_by, 'username', '') or '').strip()
    requester_email = (getattr(ticket.created_by, 'email', '') or '').strip()
    responsible_name = ticket.assigned_to.full_name if ticket.assigned_to else ''
    collaborators = ', '.join(
        [u.full_name for u in ticket.collaborators.all() if (u.full_name or '').strip()]
    )
    created_at = timezone.localtime(ticket.created_at).strftime('%d/%m/%Y %H:%M') if ticket.created_at else ''
    updated_at = timezone.localtime(ticket.updated_at).strftime('%d/%m/%Y %H:%M') if ticket.updated_at else ''
    ticket_url = f"{getattr(settings, 'SITE_BASE_URL', '').rstrip('/')}/chamados/" if getattr(settings, 'SITE_BASE_URL', '') else ''

    templates = _get_whatsapp_templates()
    payload = _SafeDict(
        {
            'id': ticket.id,
            'ticket_id': ticket.id,
            'title': title,
            'titulo': title,
            'description': description,
            'descricao': description,
            'status': ticket.get_status_display(),
            'tipo': ticket.get_ticket_type_display(),
            'urgencia': ticket.get_urgency_display(),
            'responsavel': ticket.assigned_to.full_name if ticket.assigned_to else '',
            'responsavel_usuario': ticket.assigned_to.username if ticket.assigned_to and ticket.assigned_to.username else '',
            'solicitante': requester_name,
            'solicitante_usuario': requester_username,
            'solicitante_email': requester_email,
            'colaboradores': collaborators,
            'criado_em': created_at,
            'atualizado_em': updated_at,
            'resolucao': (ticket.resolution or '').strip(),
            'link': ticket_url,
            'message': detail or description or title,
            'mensagem': detail or description or title,
        }
    )

    if 'nova mensagem' in label:
        return (templates.new_message or DEFAULT_WA_TEMPLATES['new_message']).format_map(payload)
    if 'status atualizado' in label or 'atualizado' in label:
        return (templates.status_update or DEFAULT_WA_TEMPLATES['status_update']).format_map(payload)
    return (templates.new_ticket or DEFAULT_WA_TEMPLATES['new_ticket']).format_map(payload)


def _notify_whatsapp(ticket, event_type="new_ticket", event_label="Novo chamado", extra_line=None):
    settings_obj = _get_whatsapp_settings()
    group_jid = _get_whatsapp_group_jid(settings_obj)
    summary = _build_whatsapp_summary(ticket, event_label=event_label, extra_line=extra_line)

    send_group = False
    send_individual = False
    if event_type == "new_ticket":
        send_group = settings_obj.send_group_on_new_ticket
        send_individual = settings_obj.send_individual_on_new_ticket
    elif event_type == "assignment_new":
        send_group = settings_obj.send_group_on_assignment_new
        send_individual = settings_obj.send_individual_on_assignment_new
    elif event_type == "assignment_changed":
        send_group = settings_obj.send_group_on_assignment_changed
        send_individual = settings_obj.send_individual_on_assignment_changed
    elif event_type == "status_pending":
        send_group = settings_obj.send_group_on_status_pending
        send_individual = settings_obj.send_individual_on_status_pending
    elif event_type == "status_in_progress":
        send_group = settings_obj.send_group_on_status_in_progress
        send_individual = settings_obj.send_individual_on_status_in_progress
    elif event_type == "status_closed":
        send_group = settings_obj.send_group_on_status_closed
        send_individual = settings_obj.send_individual_on_status_closed
    elif event_type == "message_internal":
        send_group = settings_obj.send_group_on_message_internal
        send_individual = settings_obj.send_individual_on_message_internal
    elif event_type == "message_user":
        send_group = settings_obj.send_group_on_message_user
        send_individual = settings_obj.send_individual_on_message_user

    if send_group and group_jid:
        try:
            send_whatsapp_message(group_jid, summary)
        except Exception:
            logger.exception("Nao foi possivel notificar o grupo WhatsApp %s", group_jid)

    if send_individual:
        for phone in _get_attendant_numbers(ticket):
            try:
                send_whatsapp_message(phone, summary)
            except Exception:
                logger.exception("Nao foi possivel notificar o atendente %s", phone)


def _notify_ticket_email(ticket, event_label="Novo chamado", extra_line=None):
    creator_username = (getattr(ticket.created_by, 'username', '') or '').strip()
    if creator_username:
        ti_user = ERPUser.objects.filter(username__iexact=creator_username).first()
        if ti_user and (ti_user.department or '').strip().upper() == 'TI':
            return
    recipient = (getattr(ticket.created_by, 'email', '') or '').strip()
    if recipient and (';' in recipient or ',' in recipient):
        recipient = (recipient.replace(',', ';').split(';', 1)[0] or '').strip()
    if not recipient:
        return
    templates = _get_email_templates()
    title = shorten((ticket.title or "").strip(), width=120, placeholder='...')
    description = shorten((ticket.description or "").strip(), width=200, placeholder='...')
    detail = shorten(((extra_line or "").replace('\n', ' ')).strip(), width=200, placeholder='...')
    payload = _SafeDict(
        {
            'id': ticket.id,
            'title': title,
            'description': description,
            'status': ticket.get_status_display(),
            'responsavel': ticket.assigned_to.full_name if ticket.assigned_to else '',
            'message': detail or description or title,
        }
    )
    label = (event_label or '').strip().lower()
    if 'nova mensagem' in label:
        subject = (templates.new_message_subject or DEFAULT_EMAIL_TEMPLATES['new_message_subject']).format_map(payload)
        body = (templates.new_message_body or DEFAULT_EMAIL_TEMPLATES['new_message_body']).format_map(payload)
    elif 'status atualizado' in label or 'atualizado' in label or 'em atendimento' in label:
        subject = (templates.status_update_subject or DEFAULT_EMAIL_TEMPLATES['status_update_subject']).format_map(payload)
        body = (templates.status_update_body or DEFAULT_EMAIL_TEMPLATES['status_update_body']).format_map(payload)
    else:
        subject = (templates.new_ticket_subject or DEFAULT_EMAIL_TEMPLATES['new_ticket_subject']).format_map(payload)
        body = (templates.new_ticket_body or DEFAULT_EMAIL_TEMPLATES['new_ticket_body']).format_map(payload)
    try:
        send_mail(
            subject,
            body,
            settings.DEFAULT_FROM_EMAIL,
            [recipient],
            fail_silently=False,
        )
    except Exception:
        logger.exception("Erro ao enviar e-mail para %s", recipient)


def _notify_new_ticket_watchers_email(ticket):
    usernames = getattr(settings, 'EMAIL_NOTIFY_NEW_TICKET_USERNAMES', []) or []
    if not usernames:
        return

    normalized = sorted({(item or '').strip().lower() for item in usernames if (item or '').strip()})
    if not normalized:
        return

    erp_users = ERPUser.objects.filter(username__in=normalized)
    erp_map = {str(u.username or '').strip().lower(): u for u in erp_users}
    User = get_user_model()
    auth_users = User.objects.filter(username__in=normalized)
    auth_map = {str(u.username or '').strip().lower(): u for u in auth_users}

    recipients = []
    seen = set()
    for username in normalized:
        email = ''
        erp_user = erp_map.get(username)
        auth_user = auth_map.get(username)
        if erp_user and (erp_user.department or '').strip().upper() == 'TI':
            continue
        if erp_user and erp_user.email:
            email = erp_user.email.strip()
        elif auth_user and auth_user.email:
            email = auth_user.email.strip()
        if not email:
            continue
        if email.lower() in seen:
            continue
        seen.add(email.lower())
        recipients.append(email)

    if not recipients:
        return

    templates = _get_email_templates()
    title = shorten((ticket.title or "").strip(), width=120, placeholder='...')
    description = shorten((ticket.description or "").strip(), width=200, placeholder='...')
    payload = _SafeDict(
        {
            'id': ticket.id,
            'title': title,
            'description': description,
            'status': ticket.get_status_display(),
            'responsavel': ticket.assigned_to.full_name if ticket.assigned_to else '',
            'message': description or title,
        }
    )
    subject = (templates.new_ticket_subject or DEFAULT_EMAIL_TEMPLATES['new_ticket_subject']).format_map(payload)
    body = (templates.new_ticket_body or DEFAULT_EMAIL_TEMPLATES['new_ticket_body']).format_map(payload)

    try:
        send_mail(
            subject,
            body,
            settings.DEFAULT_FROM_EMAIL,
            recipients,
            fail_silently=False,
        )
    except Exception:
        logger.exception("Erro ao enviar e-mail de novo chamado para observadores: %s", ', '.join(recipients))


def is_ti_user(request) -> bool:
    username = getattr(request.user, 'username', '')
    if not username:
        return False
    user = ERPUser.objects.filter(username__iexact=username).first()
    if not user:
        return False
    return (user.department or '').strip().upper() == 'TI'


def _timeline_status_label(status_code: str) -> str:
    mapping = dict(Ticket.Status.choices)
    return mapping.get(status_code, status_code or '-')


def _log_ticket_timeline(
    *,
    ticket: Ticket,
    event_type: str,
    request_user,
    from_status: str = '',
    to_status: str = '',
    note: str = '',
):
    actor_ti = None
    username = getattr(request_user, 'username', '')
    if username:
        actor_ti = ERPUser.objects.filter(username__iexact=username).first()

    TicketTimelineEvent.objects.create(
        ticket=ticket,
        event_type=event_type,
        from_status=from_status or '',
        to_status=to_status or '',
        actor_user=request_user if getattr(request_user, 'is_authenticated', False) else None,
        actor_ti=actor_ti,
        note=(note or '').strip(),
    )


def _create_ticket_work_log(
    *,
    ticket: Ticket,
    source_target: str,
    opened_at,
    closed_at,
    failure_type: str,
    action_text: str,
):
    if not source_target.startswith('user_'):
        return
    try:
        attendant_id = int(source_target.replace('user_', ''))
    except ValueError:
        return
    attendant = ERPUser.objects.filter(id=attendant_id).first()
    if not attendant:
        return
    TicketWorkLog.objects.create(
        ticket=ticket,
        attendant=attendant,
        opened_at=opened_at,
        closed_at=closed_at,
        failure_type=failure_type,
        action_text=(action_text or '').strip(),
        priority_label=ticket.get_urgency_display(),
    )


class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = 'core/dashboard.html'

    def get(self, request, *args, **kwargs):
        if not is_ti_user(request):
            return redirect('chamados')
        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        is_ti = is_ti_user(self.request)
        active_slug = ERP_MODULES[0]['slug'] if is_ti and ERP_MODULES else None
        context['is_ti_group'] = is_ti
        context['modules'] = build_modules(active_slug) if is_ti else []
        return context


class CustomLoginView(auth_views.LoginView):
    template_name = 'auth/login.html'

    def get_success_url(self):
        if is_ti_user(self.request):
            return reverse('usuarios')
        return reverse('chamados')


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


class EquipamentosView(LoginRequiredMixin, TemplateView):
    template_name = 'core/equipamentos.html'

    def post(self, request, *args, **kwargs):
        if not is_ti_user(request):
            messages.error(request, 'Apenas usuários do departamento TI podem cadastrar equipamentos.')
            return self.get(request, *args, **kwargs)

        action = (request.POST.get('action') or '').strip().lower()
        if action == 'sync_inventory':
            hosts_text = (request.POST.get('inventory_hosts') or '').strip()
            hosts = parse_hosts_text(hosts_text) or parse_hosts_text(_inventory_default_hosts())
            if not hosts:
                messages.error(request, 'Informe pelo menos um host para inventariar (ex.: PC01,PC02).')
                return self.get(request, *args, **kwargs)
            timeout_seconds = int(getattr(settings, 'INVENTORY_POWERSHELL_TIMEOUT', 120) or 120)
            result = sync_network_inventory(hosts=hosts, timeout_seconds=timeout_seconds)
            stamp = format_inventory_run_stamp()
            if result['ok']:
                messages.success(
                    request,
                    f'Inventário executado em {stamp}: {result["ok"]} host(s) atualizado(s), {result["failed"]} falha(s).',
                )
            else:
                messages.error(request, f'Inventário executado em {stamp}: nenhuma máquina atualizada.')
            for line in result.get('messages', [])[:15]:
                if 'erro' in line.lower():
                    messages.error(request, line)
                else:
                    messages.info(request, line)
            return self.get(request, *args, **kwargs)

        Equipment.objects.create(
            sector=request.POST.get('sector', '').strip(),
            user=request.POST.get('user', '').strip(),
            hostname=request.POST.get('hostname', '').strip(),
            equipment=request.POST.get('equipment', '').strip(),
            model=request.POST.get('model', '').strip(),
            brand=request.POST.get('brand', '').strip(),
            serial=request.POST.get('serial', '').strip(),
            memory=request.POST.get('memory', '').strip(),
            processor=request.POST.get('processor', '').strip(),
            generation=request.POST.get('generation', '').strip(),
            hd=request.POST.get('hd', '').strip(),
            mod_hd=request.POST.get('mod_hd', '').strip(),
            windows=request.POST.get('windows', '').strip(),
        )
        messages.success(request, 'Equipamento cadastrado com sucesso.')
        return self.get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        is_ti = is_ti_user(self.request)
        context['is_ti_group'] = is_ti
        context['modules'] = build_modules('equipamentos') if is_ti else []
        context['equipments'] = Equipment.objects.all().order_by('-created_at')
        context['inventory_default_hosts'] = _inventory_default_hosts()
        context['inventory_timeout_seconds'] = int(getattr(settings, 'INVENTORY_POWERSHELL_TIMEOUT', 120) or 120)
        return context


class SoftwaresView(LoginRequiredMixin, TemplateView):
    template_name = 'core/softwares.html'

    def post(self, request, *args, **kwargs):
        if not is_ti_user(request):
            messages.error(request, 'Apenas usuários do departamento TI podem atualizar inventário de software.')
            return self.get(request, *args, **kwargs)

        action = (request.POST.get('action') or '').strip().lower()
        if action != 'sync_inventory':
            return self.get(request, *args, **kwargs)

        hosts_text = (request.POST.get('inventory_hosts') or '').strip()
        hosts = parse_hosts_text(hosts_text) or parse_hosts_text(_inventory_default_hosts())
        if not hosts:
            messages.error(request, 'Informe pelo menos um host para inventariar (ex.: PC01,PC02).')
            return self.get(request, *args, **kwargs)

        timeout_seconds = int(getattr(settings, 'INVENTORY_POWERSHELL_TIMEOUT', 120) or 120)
        result = sync_network_inventory(hosts=hosts, timeout_seconds=timeout_seconds)
        stamp = format_inventory_run_stamp()
        if result['ok']:
            messages.success(
                request,
                f'Inventário executado em {stamp}: {result["ok"]} host(s) atualizado(s), {result["failed"]} falha(s).',
            )
        else:
            messages.error(request, f'Inventário executado em {stamp}: nenhuma máquina atualizada.')
        for line in result.get('messages', [])[:15]:
            if 'erro' in line.lower():
                messages.error(request, line)
            else:
                messages.info(request, line)
        return self.get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        is_ti = is_ti_user(self.request)
        context['is_ti_group'] = is_ti
        context['modules'] = build_modules('softwares') if is_ti else []
        context['software_items'] = SoftwareInventory.objects.select_related('equipment').order_by(
            '-collected_at', '-updated_at', 'hostname', 'software_name'
        )
        context['inventory_default_hosts'] = _inventory_default_hosts()
        context['inventory_timeout_seconds'] = int(getattr(settings, 'INVENTORY_POWERSHELL_TIMEOUT', 120) or 120)
        return context


class RequisicoesView(LoginRequiredMixin, TemplateView):
    template_name = 'core/requisicoes.html'

    @staticmethod
    def _parse_decimal_br(raw_value: str) -> Decimal:
        normalized_value = (raw_value or '').strip().replace(' ', '')
        if ',' in normalized_value and '.' in normalized_value:
            if normalized_value.rfind(',') > normalized_value.rfind('.'):
                normalized_value = normalized_value.replace('.', '').replace(',', '.')
            else:
                normalized_value = normalized_value.replace(',', '')
        elif ',' in normalized_value:
            normalized_value = normalized_value.replace('.', '').replace(',', '.')
        elif normalized_value.count('.') > 1:
            normalized_value = normalized_value.replace('.', '')
        value = Decimal(normalized_value or '0')
        if value < 0:
            raise InvalidOperation
        return value

    def _save_quotes(self, request, requisition: Requisition, update_mode: bool = False) -> tuple[int, str | None]:
        existing_quotes = {}
        if update_mode:
            existing_quotes = {str(item.id): item for item in requisition.quotes.all()}
        kept_ids: set[int] = set()
        idx_to_quote: dict[str, RequisitionQuote] = {}
        saved_count = 0

        for idx in request.POST.getlist('budget_index'):
            idx = (idx or '').strip()
            if not idx:
                continue

            quote_id = (request.POST.get(f'budget_quote_id_{idx}') or '').strip()
            source_quote_id = (request.POST.get(f'budget_source_quote_id_{idx}') or '').strip()
            name = (request.POST.get(f'budget_name_{idx}') or '').strip()
            quantity_raw = (request.POST.get(f'budget_quantity_{idx}') or '').strip()
            value_raw = (request.POST.get(f'budget_value_{idx}') or '').strip()
            freight_raw = (request.POST.get(f'budget_freight_{idx}') or '').strip()
            link = (request.POST.get(f'budget_link_{idx}') or '').strip()
            photo = request.FILES.get(f'budget_photo_{idx}')

            if not name and not value_raw and not link and not photo and not quote_id:
                continue

            if not name:
                return 0, f'Orçamento #{idx}: informe o nome.'
            try:
                quantity = int(quantity_raw or '1')
            except ValueError:
                return 0, f'Orçamento #{idx}: quantidade inválida.'
            if quantity <= 0:
                return 0, f'Orçamento #{idx}: quantidade deve ser maior que zero.'

            try:
                value = self._parse_decimal_br(value_raw)
            except (InvalidOperation, ValueError):
                return 0, f'Orçamento #{idx}: valor inválido.'
            try:
                freight = self._parse_decimal_br(freight_raw or '0')
            except (InvalidOperation, ValueError):
                return 0, f'Orçamento #{idx}: frete inválido.'

            if update_mode and quote_id and quote_id in existing_quotes:
                quote = existing_quotes[quote_id]
                quote.name = name
                quote.quantity = quantity
                quote.value = value
                quote.freight = freight
                quote.link = link
                quote.parent = None
                quote.is_selected = False
                if photo:
                    quote.photo = photo
                    quote.save()
                else:
                    quote.save(update_fields=['name', 'quantity', 'value', 'freight', 'link', 'parent', 'is_selected'])
                kept_ids.add(quote.id)
                idx_to_quote[idx] = quote
                saved_count += 1
                continue

            created = RequisitionQuote.objects.create(
                requisition=requisition,
                parent=None,
                name=name,
                quantity=quantity,
                value=value,
                freight=freight,
                is_selected=False,
                link=link,
                photo=photo,
            )
            if not photo and source_quote_id:
                source_quote = RequisitionQuote.objects.filter(id=source_quote_id).first()
                if source_quote and source_quote.photo:
                    created.photo = source_quote.photo.name
                    created.save(update_fields=['photo'])
            kept_ids.add(created.id)
            idx_to_quote[idx] = created
            saved_count += 1

        if saved_count == 0:
            return 0, 'Cadastre pelo menos um orçamento.'

        id_to_quote = {str(item.id): item for item in idx_to_quote.values()}
        for idx, quote in idx_to_quote.items():
            parent_idx = (request.POST.get(f'budget_parent_idx_{idx}') or '').strip()
            parent_quote_id = (request.POST.get(f'budget_parent_quote_id_{idx}') or '').strip()
            parent_quote = None
            if parent_quote_id and parent_quote_id in id_to_quote:
                parent_quote = id_to_quote[parent_quote_id]
            elif parent_idx and parent_idx in idx_to_quote:
                parent_quote = idx_to_quote[parent_idx]
            if parent_quote and parent_quote.id != quote.id and quote.parent_id != parent_quote.id:
                quote.parent = parent_quote
                quote.save(update_fields=['parent'])

        selected_idx = (request.POST.get('approved_budget_idx') or '').strip()
        selected_quote = idx_to_quote.get(selected_idx) if selected_idx else None
        if selected_quote and selected_quote.parent_id:
            return 0, 'Selecione como aprovado apenas um orçamento principal.'

        requisition.quotes.update(is_selected=False)
        if selected_quote:
            selected_quote.is_selected = True
            selected_quote.save(update_fields=['is_selected'])

        if update_mode:
            requisition.quotes.exclude(id__in=kept_ids).delete()
        return saved_count, None

    @staticmethod
    def _sync_requisition_status_with_approved_quote(requisition: Requisition) -> None:
        has_selected_main = requisition.quotes.filter(parent__isnull=True, is_selected=True).exists()
        status_before = requisition.status
        if has_selected_main and requisition.status == Requisition.Status.PENDING_APPROVAL:
            requisition.status = Requisition.Status.APPROVED
        elif not has_selected_main and requisition.status == Requisition.Status.APPROVED:
            requisition.status = Requisition.Status.PENDING_APPROVAL
        if requisition.status != status_before:
            requisition.save(update_fields=['status', 'updated_at'])

    @staticmethod
    def _sync_requisition_timeline_dates(requisition: Requisition) -> None:
        update_fields: list[str] = []
        if not requisition.requested_at:
            requisition.requested_at = requisition.created_at.date() if requisition.created_at else timezone.localdate()
            update_fields.append('requested_at')

        if requisition.status in {Requisition.Status.APPROVED, Requisition.Status.RECEIVED} and not requisition.approved_at:
            requisition.approved_at = timezone.localdate()
            update_fields.append('approved_at')

        if requisition.status == Requisition.Status.RECEIVED and not requisition.received_at:
            requisition.received_at = timezone.localdate()
            update_fields.append('received_at')

        if update_fields:
            requisition.save(update_fields=update_fields)

    def post(self, request, *args, **kwargs):
        if not is_ti_user(request):
            messages.error(request, 'Apenas usuários do departamento TI podem cadastrar requisições.')
            return self.get(request, *args, **kwargs)

        mode = (request.POST.get('mode') or 'create').strip().lower()
        title_text = (request.POST.get('title') or '').strip()
        if not title_text:
            messages.error(request, 'Informe o título da requisição.')
            return self.get(request, *args, **kwargs)

        request_text = (request.POST.get('request_text') or '').strip()
        if not request_text:
            messages.error(request, 'Informe o texto da requisição.')
            return self.get(request, *args, **kwargs)

        if mode == 'update':
            requisition_id = (request.POST.get('requisition_id') or '').strip()
            requisition = Requisition.objects.filter(id=requisition_id).first()
            if not requisition:
                messages.error(request, 'Requisição não encontrada para edição.')
                return self.get(request, *args, **kwargs)

            status_value = (request.POST.get('status') or Requisition.Status.PENDING_APPROVAL).strip()
            valid_statuses = {choice[0] for choice in Requisition.Status.choices}
            if status_value not in valid_statuses:
                status_value = Requisition.Status.PENDING_APPROVAL

            requisition.title = title_text
            requisition.request = request_text
            requisition.status = status_value
            requisition.save(update_fields=['title', 'request', 'status', 'updated_at'])

            saved_count, error = self._save_quotes(request, requisition, update_mode=True)
            if error:
                messages.error(request, error)
                return self.get(request, *args, **kwargs)
            self._sync_requisition_status_with_approved_quote(requisition)
            self._sync_requisition_timeline_dates(requisition)

            messages.success(request, f'Requisição atualizada com sucesso com {saved_count} orçamento(s).')
            return redirect('requisicoes')

        requisition = Requisition.objects.create(
            title=title_text,
            request=request_text,
            requested_at=timezone.localdate(),
            status=Requisition.Status.PENDING_APPROVAL,
        )

        created_quotes, error = self._save_quotes(request, requisition, update_mode=False)
        if error:
            requisition.delete()
            messages.error(request, error)
            return self.get(request, *args, **kwargs)
        self._sync_requisition_status_with_approved_quote(requisition)
        self._sync_requisition_timeline_dates(requisition)

        messages.success(request, f'Requisição cadastrada com sucesso com {created_quotes} orçamento(s).')
        return redirect('requisicoes')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        is_ti = is_ti_user(self.request)
        context['is_ti_group'] = is_ti
        context['modules'] = build_modules('requisicoes') if is_ti else []
        requisitions = (
            Requisition.objects
            .prefetch_related('quotes__subquotes')
            .order_by('-created_at', '-id')
        )
        for req in requisitions:
            all_quotes = list(req.quotes.all())
            subs_by_parent: dict[int, list[RequisitionQuote]] = {}
            main_quotes: list[RequisitionQuote] = []
            selected_main: RequisitionQuote | None = None
            for quote in all_quotes:
                if quote.parent_id:
                    subs_by_parent.setdefault(quote.parent_id, []).append(quote)
                    continue
                main_quotes.append(quote)
                if quote.is_selected:
                    selected_main = quote

            for quote in main_quotes:
                quote.sub_items = subs_by_parent.get(quote.id, [])
                quote.sub_items_count = len(quote.sub_items)
                package_total = (Decimal(quote.quantity or 1) * (quote.value or Decimal('0'))) + (quote.freight or Decimal('0'))
                for sub_item in quote.sub_items:
                    package_total += (Decimal(sub_item.quantity or 1) * (sub_item.value or Decimal('0'))) + (sub_item.freight or Decimal('0'))
                quote.package_total = package_total

            req.main_quotes = main_quotes
            req.main_quotes_count = len(main_quotes)
            req.sub_quotes_count = max(0, len(all_quotes) - len(main_quotes))
            req.approved_quote_id = selected_main.id if selected_main else None

            if selected_main:
                total = (Decimal(selected_main.quantity or 1) * (selected_main.value or Decimal('0'))) + (selected_main.freight or Decimal('0'))
                for sub_item in getattr(selected_main, 'sub_items', []):
                    total += (Decimal(sub_item.quantity or 1) * (sub_item.value or Decimal('0'))) + (sub_item.freight or Decimal('0'))
                req.quotes_total = total
            else:
                req.quotes_total = None
        context['requisitions'] = requisitions
        return context


class AcessosView(LoginRequiredMixin, TemplateView):
    template_name = 'core/acessos.html'

    def post(self, request, *args, **kwargs):
        if not is_ti_user(request):
            messages.error(request, 'Apenas usuários do departamento TI podem atualizar acessos.')
            return self.get(request, *args, **kwargs)

        root_path = getattr(settings, 'ACCESS_ROOT_PATH', '')
        try:
            folders, groups, members = refresh_access_snapshot(root_path)
            messages.success(request, f'Atualização concluída: {folders} pastas, {groups} grupos, {members} membros.')
        except Exception as exc:
            messages.error(request, f'Falha ao atualizar acessos: {exc}')
        return self.get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        is_ti = is_ti_user(self.request)
        context['is_ti_group'] = is_ti
        context['modules'] = build_modules('acessos') if is_ti else []
        folders = AccessFolder.objects.prefetch_related('groups__members').order_by('name')
        context['folders'] = folders
        users = ERPUser.objects.filter(is_active=True).order_by('full_name')
        context['access_users'] = users
        selected_user_id = self.request.GET.get('user') or ''
        context['selected_user_id'] = selected_user_id
        context['user_access'] = []
        context['user_groups'] = []
        context['user_ad_groups'] = []
        if selected_user_id:
            selected_user = ERPUser.objects.filter(id=selected_user_id).first()
            if selected_user and selected_user.username:
                context['user_ad_groups'] = _get_user_ad_groups(selected_user.username)
                memberships = (
                    AccessMember.objects.select_related('group__folder')
                    .filter(username__iexact=selected_user.username)
                )
                context['user_groups'] = sorted({m.group.name for m in memberships}, key=lambda v: v.lower())
                access_map: dict[int, dict[str, str | set[str]]] = {}
                admin_group_names: set[str] = set()

                for ad_group in context['user_ad_groups']:
                    normalized_ad = _normalize_text(ad_group)
                    if 'admin' in normalized_ad or 'administrador' in normalized_ad:
                        admin_group_names.add(ad_group)

                for member in memberships:
                    folder = member.group.folder
                    entry = access_map.setdefault(
                        folder.id,
                        {
                            'folder': folder.name,
                            'level': 'leitura',
                            'groups': set(),
                        },
                    )
                    entry['groups'].add(member.group.name)
                    if member.group.access_level == 'leitura_escrita':
                        entry['level'] = 'leitura_escrita'
                    normalized = _normalize_text(member.group.name)
                    if 'admin' in normalized or 'administrador' in normalized:
                        admin_group_names.add(member.group.name)

                # Users in administrative groups are treated as full-access for all folders.
                if admin_group_names:
                    admin_label = ', '.join(sorted(admin_group_names))
                    for folder in folders:
                        entry = access_map.setdefault(
                            folder.id,
                            {
                                'folder': folder.name,
                                'level': 'leitura_escrita',
                                'groups': set(),
                            },
                        )
                        entry['level'] = 'leitura_escrita'
                        entry['groups'].add(admin_label)
                context['user_access'] = sorted(
                    [
                        {
                            'folder': value['folder'],
                            'level': value['level'],
                            'groups': ', '.join(sorted(value['groups'])),
                        }
                        for value in access_map.values()
                    ],
                    key=lambda item: item['folder'].lower(),
                )
        return context


class ChamadosView(LoginRequiredMixin, TemplateView):
    template_name = 'core/chamados.html'

    def post(self, request, *args, **kwargs):
        is_ti = is_ti_user(request)
        title = request.POST.get('title', '').strip()
        description = request.POST.get('description', '').strip()
        ticket_type = request.POST.get('ticket_type', '').strip()
        urgency = request.POST.get('urgency', '').strip()
        attachment = request.FILES.get('attachment')

        if not title or not description:
            messages.error(request, 'Preencha título e descrição.')
            return self.get(request, *args, **kwargs)

        if not is_ti:
            valid_types = {
                choice[0]
                for choice in Ticket.TicketType.choices
                if choice[0] != Ticket.TicketType.NAO_CLASSIFICADO
            }
            valid_urgencies = {
                choice[0]
                for choice in Ticket.Urgency.choices
                if choice[0] != Ticket.Urgency.NAO_CLASSIFICADO
            }
            if ticket_type not in valid_types:
                ticket_type = Ticket.TicketType.NAO_CLASSIFICADO
            if urgency not in valid_urgencies:
                urgency = Ticket.Urgency.NAO_CLASSIFICADO
        elif not ticket_type or not urgency:
            messages.error(request, 'Preencha tipo e urgência.')
            return self.get(request, *args, **kwargs)

        recent_cutoff = timezone.now() - timedelta(seconds=30)
        duplicate = Ticket.objects.filter(
            created_by=request.user,
            title=title,
            description=description,
            created_at__gte=recent_cutoff,
        ).exists()
        if duplicate:
            messages.info(request, 'Chamado idêntico detectado recentemente. Não foi criado novamente.')
            return redirect('chamados')

        initial_status = Ticket.Status.PROGRAMADO if is_ti else Ticket.Status.NOVO
        ticket = Ticket.objects.create(
            title=title,
            description=description,
            ticket_type=ticket_type,
            urgency=urgency,
            status=initial_status,
            created_by=request.user,
            attachment=attachment,
        )
        _log_ticket_timeline(
            ticket=ticket,
            event_type=TicketTimelineEvent.EventType.CREATED,
            request_user=request.user,
            to_status=initial_status,
            note=f'Chamado criado no quadro como {_timeline_status_label(initial_status)}.',
        )
        _notify_whatsapp(ticket, event_type="new_ticket", event_label="Novo chamado")
        _notify_new_ticket_watchers_email(ticket)
        messages.success(request, 'Chamado aberto com sucesso.')
        return redirect('chamados')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        is_ti = is_ti_user(self.request)
        context['is_ti_group'] = is_ti
        context['modules'] = build_modules('chamados') if is_ti else []
        if is_ti:
            wa_settings = _get_whatsapp_settings()
            context['whatsapp_group'] = _get_whatsapp_group_jid(wa_settings)
            templates = _get_whatsapp_templates()
            context['wa_templates'] = {
                'new_ticket': templates.new_ticket,
                'status_update': templates.status_update,
                'new_message': templates.new_message,
            }
            context['wa_settings'] = {
                'group_jid': wa_settings.group_jid,
                'send_group_on_new_ticket': wa_settings.send_group_on_new_ticket,
                'send_group_on_assignment_new': wa_settings.send_group_on_assignment_new,
                'send_group_on_assignment_changed': wa_settings.send_group_on_assignment_changed,
                'send_group_on_status_pending': wa_settings.send_group_on_status_pending,
                'send_group_on_status_in_progress': wa_settings.send_group_on_status_in_progress,
                'send_group_on_status_closed': wa_settings.send_group_on_status_closed,
                'send_group_on_message_internal': wa_settings.send_group_on_message_internal,
                'send_group_on_message_user': wa_settings.send_group_on_message_user,
                'send_individual_on_new_ticket': wa_settings.send_individual_on_new_ticket,
                'send_individual_on_assignment_new': wa_settings.send_individual_on_assignment_new,
                'send_individual_on_assignment_changed': wa_settings.send_individual_on_assignment_changed,
                'send_individual_on_status_pending': wa_settings.send_individual_on_status_pending,
                'send_individual_on_status_in_progress': wa_settings.send_individual_on_status_in_progress,
                'send_individual_on_status_closed': wa_settings.send_individual_on_status_closed,
                'send_individual_on_message_internal': wa_settings.send_individual_on_message_internal,
                'send_individual_on_message_user': wa_settings.send_individual_on_message_user,
            }
            email_templates = _get_email_templates()
            context['email_templates'] = {
                'new_ticket_subject': email_templates.new_ticket_subject,
                'new_ticket_body': email_templates.new_ticket_body,
                'status_update_subject': email_templates.status_update_subject,
                'status_update_body': email_templates.status_update_body,
                'new_message_subject': email_templates.new_message_subject,
                'new_message_body': email_templates.new_message_body,
            }
            ti_users_list = list(ERPUser.objects.filter(department__iexact='TI', is_active=True).order_by('full_name'))
            contacts = []
            for user in ti_users_list:
                phone = user.mobile or user.phone or ''
                contacts.append(
                    {
                        'id': user.id,
                        'name': user.full_name,
                        'department': user.department,
                        'phone': phone,
                    }
                )
            context['wa_contacts'] = contacts
            context['chamados_xlsx_default_path'] = getattr(settings, 'CHAMADOS_XLSX_PATH', '')
        if not is_ti:
            context['own_tickets'] = (
                Ticket.objects.filter(created_by=self.request.user).order_by('-created_at')
            )
            return context

        ti_users = list(ERPUser.objects.filter(department__iexact='TI', is_active=True).order_by('full_name'))
        context['ti_users'] = ti_users
        context['new_tickets'] = Ticket.objects.filter(status=Ticket.Status.NOVO).select_related('created_by').order_by('created_at')
        context['pending_tickets'] = Ticket.objects.filter(status=Ticket.Status.PENDENTE).select_related('created_by').order_by('created_at')
        context['scheduled_tickets'] = Ticket.objects.filter(status=Ticket.Status.PROGRAMADO).select_related('created_by').order_by('created_at')
        context['closed_tickets'] = Ticket.objects.filter(status=Ticket.Status.FECHADO).select_related('created_by').order_by('-created_at')
        in_progress_tickets = Ticket.objects.filter(status=Ticket.Status.EM_ATENDIMENTO).select_related('created_by').prefetch_related(
            'collaborators'
        ).order_by('created_at')
        ticket_map = {user.id: [] for user in ti_users}
        multi_assigned_ticket_ids: set[int] = set()
        for ticket in in_progress_tickets:
            ids = set()
            if ticket.assigned_to_id:
                ids.add(ticket.assigned_to_id)
            ids.update(ticket.collaborators.values_list('id', flat=True))
            if len(ids) > 1:
                multi_assigned_ticket_ids.add(ticket.id)
            for uid in ids:
                if uid in ticket_map:
                    ticket_map[uid].append(ticket)

        all_tickets = (
            list(context['new_tickets'])
            + list(context['pending_tickets'])
            + list(context['scheduled_tickets'])
            + list(context['closed_tickets'])
            + list(in_progress_tickets)
        )
        usernames = {t.created_by.username for t in all_tickets if t.created_by}
        erp_users = ERPUser.objects.filter(username__in=list(usernames))
        erp_map = {u.username.lower(): u for u in erp_users}
        ticket_meta = {}
        for ticket in all_tickets:
            username = ticket.created_by.username if ticket.created_by else ''
            erp = erp_map.get(username.lower()) if username else None
            name = erp.full_name if erp and erp.full_name else username
            dept = erp.department if erp else ''
            ticket_meta[ticket.id] = {
                'requester': name or '- ',
                'department': dept or '',
                'description': ticket.description or '',
                'is_multi_attendant': ticket.id in multi_assigned_ticket_ids,
                'failure_type': ticket.last_failure_type or '',
            }
        context['ticket_meta'] = ticket_meta

        context['user_tickets'] = ticket_map
        return context


class RelatoriosView(LoginRequiredMixin, TemplateView):
    template_name = 'core/relatorios.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        is_ti = is_ti_user(self.request)
        context['is_ti_group'] = is_ti
        context['modules'] = build_modules('relatorios') if is_ti else []
        if not is_ti:
            return context

        date_from_raw = (self.request.GET.get('date_from') or '').strip()
        date_to_raw = (self.request.GET.get('date_to') or '').strip()
        requester_raw = (self.request.GET.get('requester') or '').strip()
        assignee_raw = (self.request.GET.get('assignee') or '').strip()
        status_raw = (self.request.GET.get('status') or '').strip()
        search_raw = (self.request.GET.get('q') or '').strip()

        tickets = Ticket.objects.select_related('created_by', 'assigned_to').prefetch_related('collaborators').all()

        date_from = parse_date(date_from_raw) if date_from_raw else None
        date_to = parse_date(date_to_raw) if date_to_raw else None
        if date_from:
            tickets = tickets.filter(created_at__date__gte=date_from)
        if date_to:
            tickets = tickets.filter(created_at__date__lte=date_to)

        if requester_raw:
            try:
                tickets = tickets.filter(created_by_id=int(requester_raw))
            except ValueError:
                pass

        if assignee_raw:
            try:
                assignee_id = int(assignee_raw)
                tickets = tickets.filter(Q(assigned_to_id=assignee_id) | Q(collaborators__id=assignee_id))
            except ValueError:
                pass

        if status_raw in {choice[0] for choice in Ticket.Status.choices}:
            tickets = tickets.filter(status=status_raw)

        if search_raw:
            tickets = tickets.filter(Q(title__icontains=search_raw) | Q(description__icontains=search_raw))

        tickets = tickets.distinct()
        total_tickets = tickets.count()
        status_counts_qs = tickets.values('status').annotate(total=Count('id')).order_by('status')
        urgency_counts_qs = tickets.values('urgency').annotate(total=Count('id')).order_by('urgency')
        type_counts_qs = tickets.values('ticket_type').annotate(total=Count('id')).order_by('ticket_type')
        requester_counts_qs = (
            tickets.values('created_by__username')
            .annotate(total=Count('id'))
            .order_by('-total', 'created_by__username')[:8]
        )
        day_counts_qs = (
            tickets.annotate(day=TruncDate('created_at'))
            .values('day')
            .annotate(total=Count('id'))
            .order_by('day')
        )

        status_labels_map = dict(Ticket.Status.choices)
        urgency_labels_map = dict(Ticket.Urgency.choices)
        type_labels_map = dict(Ticket.TicketType.choices)

        status_counts = [
            {'label': status_labels_map.get(item['status'], item['status']), 'total': item['total']}
            for item in status_counts_qs
        ]
        urgency_counts = [
            {'label': urgency_labels_map.get(item['urgency'], item['urgency']), 'total': item['total']}
            for item in urgency_counts_qs
        ]
        type_counts = [
            {'label': type_labels_map.get(item['ticket_type'], item['ticket_type']), 'total': item['total']}
            for item in type_counts_qs
        ]
        requester_counts = [
            {'label': item['created_by__username'] or '(sem usuário)', 'total': item['total']}
            for item in requester_counts_qs
        ]
        day_counts = [
            {'label': item['day'].strftime('%d/%m/%Y') if item['day'] else '-', 'total': item['total']}
            for item in day_counts_qs
        ]

        all_requesters = (
            Ticket.objects.select_related('created_by')
            .exclude(created_by__isnull=True)
            .values('created_by_id', 'created_by__username')
            .distinct()
            .order_by('created_by__username')
        )
        requesters = [
            {'id': item['created_by_id'], 'label': item['created_by__username'] or '(sem usuário)'}
            for item in all_requesters
        ]
        attendants = list(ERPUser.objects.filter(department__iexact='TI', is_active=True).order_by('full_name'))

        context['filters'] = {
            'date_from': date_from_raw,
            'date_to': date_to_raw,
            'requester': requester_raw,
            'assignee': assignee_raw,
            'status': status_raw,
            'q': search_raw,
        }
        context['status_choices'] = Ticket.Status.choices
        context['requesters'] = requesters
        context['attendants'] = attendants
        context['summary'] = {
            'total': total_tickets,
            'pending': tickets.filter(status__in=[Ticket.Status.NOVO, Ticket.Status.PENDENTE, Ticket.Status.PROGRAMADO]).count(),
            'in_progress': tickets.filter(status=Ticket.Status.EM_ATENDIMENTO).count(),
            'closed': tickets.filter(status=Ticket.Status.FECHADO).count(),
        }
        context['chart_data'] = {
            'status': status_counts,
            'urgency': urgency_counts,
            'type': type_counts,
            'requesters': requester_counts,
            'days': day_counts,
        }
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

    multi = request.POST.get('multi') == '1'
    source_target = (request.POST.get('source_target') or '').strip()
    progress_note = (request.POST.get('progress_note') or '').strip()
    resolution_note = (request.POST.get('resolution') or '').strip()
    failure_type = _normalize_failure_type(request.POST.get('failure_type') or '')
    valid_failures = {choice[0] for choice in Ticket.FailureType.choices}
    if failure_type not in valid_failures:
        saved_failure = _normalize_failure_type(ticket.last_failure_type or '')
        if saved_failure in valid_failures:
            failure_type = saved_failure
    previous_status = ticket.status
    previous_assignee_id = ticket.assigned_to_id
    source_is_user = source_target.startswith('user_')

    if target in {'novo', 'pendente', 'programado'}:
        status_map = {
            'novo': Ticket.Status.NOVO,
            'pendente': Ticket.Status.PENDENTE,
            'programado': Ticket.Status.PROGRAMADO,
        }
        destination_status = status_map[target]
        if destination_status == Ticket.Status.NOVO and previous_status != Ticket.Status.NOVO:
            return JsonResponse({'ok': False, 'error': 'cannot_return_to_new'}, status=400)
        source_user_id = None
        if source_target.startswith('user_'):
            try:
                source_user_id = int(source_target.replace('user_', ''))
            except ValueError:
                source_user_id = None

        current_assignees = set()
        if ticket.assigned_to_id:
            current_assignees.add(ticket.assigned_to_id)
        current_assignees.update(ticket.collaborators.values_list('id', flat=True))

        # When the ticket is shared across attendants, dropping to queue columns from one
        # user column should remove only that attendant and keep the others working.
        if source_user_id and source_user_id in current_assignees and len(current_assignees) > 1:
            if source_is_user:
                if failure_type not in valid_failures:
                    return JsonResponse({'ok': False, 'error': 'failure_required'}, status=400)
                if not progress_note:
                    return JsonResponse({'ok': False, 'error': 'action_required'}, status=400)
                cycle_start = ticket.current_cycle_started_at or ticket.created_at
                closed_at = timezone.now()
                _create_ticket_work_log(
                    ticket=ticket,
                    source_target=source_target,
                    opened_at=cycle_start,
                    closed_at=closed_at,
                    failure_type=failure_type,
                    action_text=progress_note,
                )
                ticket.last_failure_type = failure_type
                ticket.save(update_fields=['last_failure_type', 'updated_at'])
            if ticket.assigned_to_id == source_user_id:
                remaining = [uid for uid in current_assignees if uid != source_user_id]
                promoted_id = remaining[0]
                ticket.assigned_to_id = promoted_id
                ticket.save(update_fields=['assigned_to', 'updated_at'])
                ticket.collaborators.remove(promoted_id)
            else:
                ticket.collaborators.remove(source_user_id)
            _log_ticket_timeline(
                ticket=ticket,
                event_type=TicketTimelineEvent.EventType.UNASSIGNED,
                request_user=request.user,
                from_status=previous_status,
                to_status=ticket.status,
                note=f'Atendente removido do compartilhamento ao mover para {_timeline_status_label(destination_status)}.',
            )
            return JsonResponse({'ok': True, 'partial_unassign': True})

        if source_target.startswith('user_') and destination_status == Ticket.Status.PENDENTE and not progress_note:
            return JsonResponse({'ok': False, 'error': 'progress_note_required'}, status=400)
        if source_is_user:
            if failure_type not in valid_failures:
                return JsonResponse({'ok': False, 'error': 'failure_required'}, status=400)
            if not progress_note:
                return JsonResponse({'ok': False, 'error': 'action_required'}, status=400)

            cycle_start = ticket.current_cycle_started_at or ticket.created_at
            closed_at = timezone.now()
            _create_ticket_work_log(
                ticket=ticket,
                source_target=source_target,
                opened_at=cycle_start,
                closed_at=closed_at,
                failure_type=failure_type,
                action_text=progress_note,
            )

        ticket.status = destination_status
        ticket.assigned_to = None
        ticket.last_failure_type = failure_type if source_is_user else ticket.last_failure_type
        ticket.current_cycle_started_at = None
        if destination_status != Ticket.Status.FECHADO:
            ticket.resolution = ''
        ticket.save()
        ticket.collaborators.clear()
        if previous_status != destination_status:
            _notify_whatsapp(
                ticket,
                event_type="status_pending",
                event_label="Status atualizado",
                extra_line=f"Status atual: {_timeline_status_label(destination_status)}",
            )
            _notify_ticket_email(
                ticket,
                event_label="Status atualizado",
                extra_line=f"Status atual: {_timeline_status_label(destination_status)}",
            )
        timeline_note = progress_note or f'Chamado movido para {_timeline_status_label(destination_status)}.'
        _log_ticket_timeline(
            ticket=ticket,
            event_type=TicketTimelineEvent.EventType.STATUS_CHANGED,
            request_user=request.user,
            from_status=previous_status,
            to_status=destination_status,
            note=timeline_note,
        )
        return JsonResponse({'ok': True})

    if target == 'fechado':
        if not source_is_user:
            return JsonResponse({'ok': False, 'error': 'close_only_from_attendant'}, status=400)
        if not resolution_note:
            return JsonResponse({'ok': False, 'error': 'resolution_required'}, status=400)
        if failure_type not in valid_failures:
            return JsonResponse({'ok': False, 'error': 'failure_required'}, status=400)
        cycle_start = ticket.current_cycle_started_at or ticket.created_at
        closed_at = timezone.now()
        _create_ticket_work_log(
            ticket=ticket,
            source_target=source_target,
            opened_at=cycle_start,
            closed_at=closed_at,
            failure_type=failure_type,
            action_text=resolution_note,
        )
        ticket.status = Ticket.Status.FECHADO
        ticket.resolution = resolution_note
        ticket.last_failure_type = failure_type
        ticket.current_cycle_started_at = None
        ticket.save()
        if previous_status != Ticket.Status.FECHADO:
            _notify_whatsapp(ticket, event_type="status_closed", event_label="Status atualizado", extra_line="Status atual: Fechado")
            _notify_ticket_email(ticket, event_label="Status atualizado", extra_line="Status atual: Fechado")
        _log_ticket_timeline(
            ticket=ticket,
            event_type=TicketTimelineEvent.EventType.STATUS_CHANGED,
            request_user=request.user,
            from_status=previous_status,
            to_status=Ticket.Status.FECHADO,
            note=f'Resolução registrada: {resolution_note}',
        )
        return JsonResponse({'ok': True})

    if target.startswith('user_'):
        user_id = target.replace('user_', '')
        assignee = ERPUser.objects.filter(id=user_id).first()
        if not assignee:
            return JsonResponse({'ok': False, 'error': 'user_not_found'}, status=404)
        was_closed = previous_status == Ticket.Status.FECHADO
        ticket.status = Ticket.Status.EM_ATENDIMENTO
        sent_assignment = False
        timeline_event = TicketTimelineEvent.EventType.ASSIGNED
        timeline_note = f'Chamado assumido por {assignee.full_name}.'
        is_clone_assignment = bool(multi and ticket.assigned_to_id and ticket.assigned_to_id != assignee.id)
        if source_is_user and not is_clone_assignment:
            if failure_type not in valid_failures:
                return JsonResponse({'ok': False, 'error': 'failure_required'}, status=400)
            if not progress_note:
                return JsonResponse({'ok': False, 'error': 'action_required'}, status=400)
            cycle_start = ticket.current_cycle_started_at or ticket.created_at
            closed_at = timezone.now()
            _create_ticket_work_log(
                ticket=ticket,
                source_target=source_target,
                opened_at=cycle_start,
                closed_at=closed_at,
                failure_type=failure_type,
                action_text=progress_note,
            )

        if is_clone_assignment:
            ticket.save()
            ticket.collaborators.add(assignee)
            ticket.historical_attendants.add(assignee)
            timeline_note = f'{assignee.full_name} foi adicionado como colaborador no chamado.'
        else:
            ticket.assigned_to = assignee
            if was_closed:
                ticket.resolution = ''
            ticket.current_cycle_started_at = timezone.now()
            ticket.last_failure_type = failure_type if source_is_user else ticket.last_failure_type
            ticket.save()
            ticket.collaborators.clear()
            ticket.historical_attendants.add(assignee)
            if was_closed:
                timeline_event = TicketTimelineEvent.EventType.REOPENED
                timeline_note = f'Chamado reaberto e atribuído para {assignee.full_name}.'
        if not multi:
            if previous_assignee_id is None:
                _notify_whatsapp(
                    ticket,
                    event_type="assignment_new",
                    event_label="Status atualizado",
                    extra_line=f"Responsável definido: {assignee.full_name}",
                )
                sent_assignment = True
            elif previous_assignee_id != assignee.id:
                _notify_whatsapp(
                    ticket,
                    event_type="assignment_changed",
                    event_label="Status atualizado",
                    extra_line=f"Responsável alterado: {assignee.full_name}",
                )
                sent_assignment = True
        if previous_status != Ticket.Status.EM_ATENDIMENTO and not sent_assignment:
            _notify_whatsapp(
                ticket,
                event_type="status_in_progress",
                event_label="Status atualizado",
                extra_line=f"Status atual: Em atendimento | Responsável: {assignee.full_name}",
            )
            _notify_ticket_email(
                ticket,
                event_label="Status atualizado",
                extra_line=f"Status atual: Em atendimento | Responsável: {assignee.full_name}",
            )
        _log_ticket_timeline(
            ticket=ticket,
            event_type=timeline_event,
            request_user=request.user,
            from_status=previous_status,
            to_status=Ticket.Status.EM_ATENDIMENTO,
            note=timeline_note,
        )
        return JsonResponse({'ok': True})

    return JsonResponse({'ok': False, 'error': 'invalid_target'}, status=400)


@login_required
@require_GET
def ticket_detail(request, ticket_id: int):
    ticket = (
        Ticket.objects.filter(id=ticket_id)
        .select_related('assigned_to', 'created_by')
        .prefetch_related('collaborators', 'historical_attendants', 'timeline_events__actor_user', 'timeline_events__actor_ti')
        .first()
    )
    if not ticket:
        return JsonResponse({'ok': False, 'error': 'not_found'}, status=404)

    is_ti = is_ti_user(request)
    if not is_ti and ticket.created_by_id != request.user.id:
        return JsonResponse({'ok': False, 'error': 'forbidden'}, status=403)

    messages_qs = TicketMessage.objects.filter(ticket=ticket).order_by('created_at')
    if not is_ti:
        messages_qs = messages_qs.filter(is_internal=False)

    public_messages = []
    internal_messages = []
    for msg in messages_qs:
        payload = {
            'id': msg.id,
            'author': msg.created_by.username if msg.created_by else 'Sistema',
            'message': msg.message,
            'attachment_url': msg.attachment.url if msg.attachment else '',
            'created_at': timezone.localtime(msg.created_at).strftime('%d/%m/%Y %H:%M'),
        }
        if msg.is_internal:
            internal_messages.append(payload)
        else:
            public_messages.append(payload)

    timeline_rows = []
    for row in ticket.timeline_events.select_related('actor_user', 'actor_ti').order_by('created_at'):
        actor_name = '-'
        if row.actor_ti and row.actor_ti.full_name:
            actor_name = row.actor_ti.full_name
        elif row.actor_user:
            actor_name = row.actor_user.get_full_name() or row.actor_user.username
        timeline_rows.append(
            {
                'id': row.id,
                'event_type': row.get_event_type_display(),
                'from_status': _timeline_status_label(row.from_status),
                'to_status': _timeline_status_label(row.to_status),
                'note': row.note,
                'actor': actor_name,
                'created_at': timezone.localtime(row.created_at).strftime('%d/%m/%Y %H:%M'),
            }
        )

    historical_names: list[str] = []
    seen_names: set[str] = set()
    for user in list(ticket.historical_attendants.all()) + ([ticket.assigned_to] if ticket.assigned_to else []) + list(ticket.collaborators.all()):
        if not user:
            continue
        name = (user.full_name or '').strip()
        if not name:
            continue
        key = name.lower()
        if key in seen_names:
            continue
        seen_names.add(key)
        historical_names.append(name)

    can_edit = is_ti and ticket.created_by_id == request.user.id
    data = {
        'ok': True,
        'ticket': {
            'id': ticket.id,
            'title': ticket.title,
            'description': ticket.description,
            'ticket_type': ticket.get_ticket_type_display(),
            'ticket_type_value': ticket.ticket_type,
            'urgency': ticket.get_urgency_display(),
            'urgency_value': ticket.urgency,
            'status': ticket.get_status_display(),
            'status_code': ticket.status,
            'created_by': ticket.created_by.username if ticket.created_by else '-',
            'resolution': ticket.resolution,
            'assignees': ', '.join(historical_names) or '-',
            'attachment_url': ticket.attachment.url if ticket.attachment else '',
            'created_at': timezone.localtime(ticket.created_at).strftime('%d/%m/%Y %H:%M'),
            'can_edit': can_edit,
        },
        'messages': {
            'public': public_messages,
            'internal': internal_messages,
        },
        'timeline': timeline_rows,
        'internal_allowed': is_ti,
    }
    return JsonResponse(data)


@login_required
@require_POST
def ticket_reclassify(request):
    if not is_ti_user(request):
        return JsonResponse({'ok': False, 'error': 'forbidden'}, status=403)

    ticket_id = request.POST.get('ticket_id')
    ticket_type = (request.POST.get('ticket_type') or '').strip()
    urgency = (request.POST.get('urgency') or '').strip()

    if not ticket_id or not ticket_type or not urgency:
        return JsonResponse({'ok': False, 'error': 'invalid'}, status=400)

    ticket = Ticket.objects.filter(id=ticket_id).first()
    if not ticket:
        return JsonResponse({'ok': False, 'error': 'not_found'}, status=404)

    valid_types = {choice[0] for choice in Ticket.TicketType.choices}
    valid_urgencies = {choice[0] for choice in Ticket.Urgency.choices}
    if ticket_type not in valid_types or urgency not in valid_urgencies:
        return JsonResponse({'ok': False, 'error': 'invalid'}, status=400)

    ticket.ticket_type = ticket_type
    ticket.urgency = urgency
    ticket.save(update_fields=['ticket_type', 'urgency', 'updated_at'])
    return JsonResponse({'ok': True})


@login_required
@require_POST
def ticket_message(request):
    ticket_id = request.POST.get('ticket_id')
    message = (request.POST.get('message') or '').strip()
    internal = request.POST.get('internal') == '1'
    attachment = request.FILES.get('attachment')

    if not ticket_id:
        return JsonResponse({'ok': False, 'error': 'invalid'}, status=400)

    ticket = Ticket.objects.filter(id=ticket_id).first()
    if not ticket:
        return JsonResponse({'ok': False, 'error': 'not_found'}, status=404)

    is_ti = is_ti_user(request)
    if internal and not is_ti:
        return JsonResponse({'ok': False, 'error': 'forbidden'}, status=403)
    if not is_ti and ticket.created_by_id != request.user.id:
        return JsonResponse({'ok': False, 'error': 'forbidden'}, status=403)

    if not message and not attachment:
        return JsonResponse({'ok': False, 'error': 'empty'}, status=400)

    # Protecao contra duplo submit: se a mesma mensagem textual do mesmo usuario
    # for enviada para o mesmo chamado em poucos segundos, reaproveita a existente.
    if message and not attachment:
        duplicate_cutoff = timezone.now() - timedelta(seconds=8)
        duplicate_msg = (
            TicketMessage.objects.filter(
                ticket=ticket,
                created_by=request.user,
                is_internal=internal,
                message=message,
                created_at__gte=duplicate_cutoff,
            )
            .order_by('-created_at')
            .first()
        )
        if duplicate_msg:
            return JsonResponse({'ok': True, 'duplicate': True, 'id': duplicate_msg.id})

    ticket_message = TicketMessage.objects.create(
        ticket=ticket,
        created_by=request.user,
        message=message,
        is_internal=internal,
        attachment=attachment,
    )
    author_name = request.user.username
    preview = shorten(message.strip(), width=120, placeholder='...') if message else 'Anexo enviado'
    extra = f"Mensagem de {author_name}: {preview}"
    event_type = None
    if internal:
        event_type = "message_internal"
        extra = f"(Interno) {extra}"
    elif not is_ti:
        event_type = "message_user"
    if event_type:
        _notify_whatsapp(ticket, event_type=event_type, event_label="Nova mensagem no chamado", extra_line=extra)
    if not internal:
        _notify_ticket_email(ticket, event_label="Nova mensagem no chamado", extra_line=extra)
    return JsonResponse({'ok': True})


@login_required
@require_POST
def ticket_update(request):
    if not is_ti_user(request):
        return JsonResponse({'ok': False, 'error': 'forbidden'}, status=403)

    ticket_id = request.POST.get('ticket_id')
    title = (request.POST.get('title') or '').strip()
    description = (request.POST.get('description') or '').strip()
    if not ticket_id or not title or not description:
        return JsonResponse({'ok': False, 'error': 'invalid'}, status=400)

    ticket = Ticket.objects.filter(id=ticket_id).first()
    if not ticket:
        return JsonResponse({'ok': False, 'error': 'not_found'}, status=404)
    if ticket.created_by_id != request.user.id:
        return JsonResponse({'ok': False, 'error': 'forbidden'}, status=403)

    ticket.title = title
    ticket.description = description
    ticket.save(update_fields=['title', 'description', 'updated_at'])
    return JsonResponse({'ok': True})


@login_required
@require_POST
def ticket_reopen(request):
    ticket_id = request.POST.get('ticket_id')
    if not ticket_id:
        return JsonResponse({'ok': False, 'error': 'invalid'}, status=400)

    ticket = Ticket.objects.filter(id=ticket_id).first()
    if not ticket:
        return JsonResponse({'ok': False, 'error': 'not_found'}, status=404)

    is_ti = is_ti_user(request)
    if not is_ti and ticket.created_by_id != request.user.id:
        return JsonResponse({'ok': False, 'error': 'forbidden'}, status=403)

    if ticket.status == Ticket.Status.FECHADO:
        ticket.status = Ticket.Status.PENDENTE
        ticket.resolution = ''
        ticket.current_cycle_started_at = None
        ticket.save(update_fields=['status', 'resolution', 'current_cycle_started_at', 'updated_at'])
        _notify_whatsapp(ticket, event_type="status_pending", event_label="Status atualizado", extra_line="Status atual: Pendente")
        _notify_ticket_email(ticket, event_label="Status atualizado", extra_line="Status atual: Pendente")
        _log_ticket_timeline(
            ticket=ticket,
            event_type=TicketTimelineEvent.EventType.REOPENED,
            request_user=request.user,
            from_status=Ticket.Status.FECHADO,
            to_status=Ticket.Status.PENDENTE,
            note='Chamado reaberto para a coluna Pendente.',
        )
    return JsonResponse({'ok': True})


@login_required
@require_GET
def ws_tickets_ping(request):
    return JsonResponse({'ok': True, 'transport': 'http-fallback'})


@csrf_exempt
@require_POST
def inventory_push_api(request):
    token = _inventory_agent_token()
    if not token:
        return JsonResponse({'ok': False, 'error': 'inventory_agent_token_not_configured'}, status=503)

    auth_header = (request.headers.get('Authorization') or '').strip()
    header_token = ''
    if auth_header.lower().startswith('bearer '):
        header_token = auth_header[7:].strip()
    if not header_token:
        header_token = (request.headers.get('X-Inventory-Token') or '').strip()
    if header_token != token:
        return JsonResponse({'ok': False, 'error': 'unauthorized'}, status=401)

    try:
        body_text = (request.body or b'').decode('utf-8')
        payload = json.loads(body_text or '{}')
    except Exception:
        return JsonResponse({'ok': False, 'error': 'invalid_json'}, status=400)

    items = []
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict):
        if isinstance(payload.get('items'), list):
            items = payload.get('items') or []
        else:
            items = [payload]
    else:
        return JsonResponse({'ok': False, 'error': 'invalid_payload'}, status=400)

    if not items:
        return JsonResponse({'ok': False, 'error': 'empty_payload'}, status=400)

    ok_count = 0
    failed_count = 0
    messages_list = []
    for item in items:
        if not isinstance(item, dict):
            failed_count += 1
            messages_list.append('Item inválido no payload.')
            continue
        try:
            _, message = upsert_inventory_from_payload(item, source='agent')
            ok_count += 1
            messages_list.append(message)
        except Exception as exc:
            failed_count += 1
            host = (item.get('Hostname') or item.get('hostname') or '-')
            messages_list.append(f'{host}: erro ({exc})')
            logger.exception('Falha ao processar payload de inventário do agente: host=%s', host)

    status = 200 if ok_count else 400
    return JsonResponse(
        {
            'ok': ok_count > 0,
            'processed': len(items),
            'updated': ok_count,
            'failed': failed_count,
            'messages': messages_list[:30],
        },
        status=status,
    )


@login_required
@require_POST
def chamados_fill_spreadsheet(request):
    if not is_ti_user(request):
        return JsonResponse({'ok': False, 'error': 'forbidden'}, status=403)

    attendant_id = (request.POST.get('attendant_id') or '').strip()
    workbook_path = (request.POST.get('workbook_path') or '').strip()
    workbook_file = request.FILES.get('workbook_file')
    if not attendant_id:
        messages.error(request, 'Informe o atendente.')
        return redirect('chamados')

    try:
        attendant_id_int = int(attendant_id)
    except ValueError:
        messages.error(request, 'Atendente inválido.')
        return redirect('chamados')

    attendant = ERPUser.objects.filter(id=attendant_id_int, department__iexact='TI', is_active=True).first()
    if not attendant:
        messages.error(request, 'Atendente não encontrado.')
        return redirect('chamados')

    export_path = workbook_path
    output_filename = ''
    if workbook_file:
        upload_dir = settings.MEDIA_ROOT / 'exports'
        upload_dir.mkdir(parents=True, exist_ok=True)
        suffix = Path(workbook_file.name or '').suffix.lower() or '.xlsx'
        tmp_name = f'planilha_{uuid4().hex}{suffix}'
        tmp_path = upload_dir / tmp_name
        with tmp_path.open('wb') as stream:
            for chunk in workbook_file.chunks():
                stream.write(chunk)
        export_path = str(tmp_path)
        output_filename = workbook_file.name or f'planilha_{attendant_id_int}.xlsx'

    if not export_path:
        messages.error(request, 'Informe o caminho da planilha ou selecione um arquivo.')
        return redirect('chamados')

    ok, exported_count, detail = export_attendant_logs_to_excel(
        attendant=attendant,
        workbook_path=export_path,
    )
    if ok:
        if workbook_file:
            response = FileResponse(open(export_path, 'rb'), as_attachment=True, filename=output_filename)
            response['X-Export-Result'] = detail
            return response
        messages.success(request, f'{attendant.full_name}: {detail}')
    else:
        messages.error(request, f'{attendant.full_name}: {detail}')
    return redirect('chamados')


@login_required
@require_POST
def whatsapp_templates_update(request):
    if not is_ti_user(request):
        return JsonResponse({'ok': False, 'error': 'forbidden'}, status=403)

    template = _get_whatsapp_templates()
    template.new_ticket = (request.POST.get('template_new_ticket') or '').strip() or DEFAULT_WA_TEMPLATES['new_ticket']
    template.status_update = (request.POST.get('template_status_update') or '').strip() or DEFAULT_WA_TEMPLATES['status_update']
    template.new_message = (request.POST.get('template_new_message') or '').strip() or DEFAULT_WA_TEMPLATES['new_message']
    template.save()
    messages.success(request, 'Templates de WhatsApp atualizados.')
    return redirect('chamados')


@login_required
@require_POST
def whatsapp_group_lookup(request):
    if not is_ti_user(request):
        return JsonResponse({'ok': False, 'error': 'forbidden'}, status=403)

    group_name = (request.POST.get('group_name') or '').strip()
    if not group_name:
        return JsonResponse({'ok': False, 'error': 'missing_group_name'}, status=400)

    try:
        matches = find_whatsapp_groups_by_name(group_name)
    except Exception as exc:
        return JsonResponse({'ok': False, 'error': 'lookup_failed', 'detail': str(exc)}, status=502)

    if not matches:
        return JsonResponse({'ok': True, 'found': False, 'matches': []})

    selected = matches[0]
    return JsonResponse(
        {
            'ok': True,
            'found': True,
            'jid': selected['jid'],
            'name': selected['name'],
            'matches': matches[:20],
        }
    )


@login_required
@require_POST
def whatsapp_settings_update(request):
    if not is_ti_user(request):
        return JsonResponse({'ok': False, 'error': 'forbidden'}, status=403)

    settings_obj = _get_whatsapp_settings()
    settings_obj.group_jid = (request.POST.get('group_jid') or '').strip()
    settings_obj.send_group_on_new_ticket = bool(request.POST.get('send_group_on_new_ticket'))
    settings_obj.send_group_on_assignment_new = bool(request.POST.get('send_group_on_assignment_new'))
    settings_obj.send_group_on_assignment_changed = bool(request.POST.get('send_group_on_assignment_changed'))
    settings_obj.send_group_on_status_pending = bool(request.POST.get('send_group_on_status_pending'))
    settings_obj.send_group_on_status_in_progress = bool(request.POST.get('send_group_on_status_in_progress'))
    settings_obj.send_group_on_status_closed = bool(request.POST.get('send_group_on_status_closed'))
    settings_obj.send_group_on_message_internal = bool(request.POST.get('send_group_on_message_internal'))
    settings_obj.send_group_on_message_user = bool(request.POST.get('send_group_on_message_user'))
    settings_obj.send_individual_on_new_ticket = bool(request.POST.get('send_individual_on_new_ticket'))
    settings_obj.send_individual_on_assignment_new = bool(request.POST.get('send_individual_on_assignment_new'))
    settings_obj.send_individual_on_assignment_changed = bool(request.POST.get('send_individual_on_assignment_changed'))
    settings_obj.send_individual_on_status_pending = bool(request.POST.get('send_individual_on_status_pending'))
    settings_obj.send_individual_on_status_in_progress = bool(request.POST.get('send_individual_on_status_in_progress'))
    settings_obj.send_individual_on_status_closed = bool(request.POST.get('send_individual_on_status_closed'))
    settings_obj.send_individual_on_message_internal = bool(request.POST.get('send_individual_on_message_internal'))
    settings_obj.send_individual_on_message_user = bool(request.POST.get('send_individual_on_message_user'))
    settings_obj.save()
    messages.success(request, 'Regras de notificação WhatsApp atualizadas.')
    return redirect('chamados')




@login_required
@require_POST
def email_templates_update(request):
    if not is_ti_user(request):
        return JsonResponse({'ok': False, 'error': 'forbidden'}, status=403)

    template = _get_email_templates()
    template.new_ticket_subject = (request.POST.get('email_new_ticket_subject') or '').strip() or DEFAULT_EMAIL_TEMPLATES['new_ticket_subject']
    template.new_ticket_body = (request.POST.get('email_new_ticket_body') or '').strip() or DEFAULT_EMAIL_TEMPLATES['new_ticket_body']
    template.status_update_subject = (request.POST.get('email_status_update_subject') or '').strip() or DEFAULT_EMAIL_TEMPLATES['status_update_subject']
    template.status_update_body = (request.POST.get('email_status_update_body') or '').strip() or DEFAULT_EMAIL_TEMPLATES['status_update_body']
    template.new_message_subject = (request.POST.get('email_new_message_subject') or '').strip() or DEFAULT_EMAIL_TEMPLATES['new_message_subject']
    template.new_message_body = (request.POST.get('email_new_message_body') or '').strip() or DEFAULT_EMAIL_TEMPLATES['new_message_body']
    template.save()
    messages.success(request, 'Templates de e-mail atualizados.')
    return redirect('chamados')




