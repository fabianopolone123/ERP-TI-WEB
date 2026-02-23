import logging
import json
import unicodedata
from uuid import uuid4
from textwrap import shorten
from decimal import Decimal, InvalidOperation
from django.conf import settings
from django.contrib import messages
from django.core.mail import send_mail
from django.db.models import Count, Q, Case, When, Value, IntegerField
from django.db.models.functions import TruncDate
from django.shortcuts import redirect
from django.utils import timezone
from datetime import datetime, timedelta
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth import get_user_model
from django.http import JsonResponse
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
    EmailAlias,
    EmailAccount,
    Equipment,
    SoftwareInventory,
    Requisition,
    RequisitionQuote,
    AccessFolder,
    AccessMember,
    Dica,
    Ticket,
    TicketMessage,
    TicketTimelineEvent,
    TicketWorkLog,
    TicketAttendantCycle,
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
    _infer_tag_code_from_hostname,
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
    {'slug': 'chamados', 'label': 'Chamados', 'url_name': 'chamados'},
    {'slug': 'usuarios', 'label': 'Usuários', 'url_name': 'usuarios'},
    {'slug': 'acessos', 'label': 'Acessos', 'url_name': 'acessos'},
    {'slug': 'equipamentos', 'label': 'Equipamentos', 'url_name': 'equipamentos'},
    {'slug': 'ips', 'label': 'IPs', 'url_name': None},
    {'slug': 'emails', 'label': 'Emails', 'url_name': None},
    {'slug': 'ramais', 'label': 'Ramais', 'url_name': None},
    {'slug': 'softwares', 'label': 'Softwares', 'url_name': 'softwares'},
    {'slug': 'insumos', 'label': 'Insumos', 'url_name': None},
    {'slug': 'requisicoes', 'label': 'Requisições', 'url_name': 'requisicoes'},
    {'slug': 'dicas', 'label': 'Dicas', 'url_name': 'dicas'},
    {'slug': 'emprestimos', 'label': 'Empréstimos', 'url_name': None},
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
        if module['slug'] == 'emails':
            url = f"{reverse('usuarios')}?tab={module['slug']}"
        else:
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


def _split_email_tokens(raw_email: str) -> list[str]:
    raw = (raw_email or '').strip()
    if not raw:
        return []
    parts = []
    for chunk in raw.replace(',', ';').split(';'):
        token = chunk.strip()
        if token and '@' in token:
            parts.append(token)
    return parts


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
    requester_email = _split_email_tokens((getattr(ticket.created_by, 'email', '') or '').strip())
    requester_email = requester_email[0] if requester_email else ''
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
    recipient_tokens = _split_email_tokens((getattr(ticket.created_by, 'email', '') or '').strip())
    recipient = recipient_tokens[0] if recipient_tokens else ''
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
            tokens = _split_email_tokens(erp_user.email.strip())
            email = tokens[0] if tokens else ''
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


def _extract_source_user_id(source_target: str) -> int | None:
    if not (source_target or '').startswith('user_'):
        return None
    try:
        return int(str(source_target).replace('user_', ''))
    except ValueError:
        return None


def _get_ticket_attendant_cycle(ticket: Ticket, attendant_id: int, create: bool = False):
    if not attendant_id:
        return None
    cycle = TicketAttendantCycle.objects.filter(ticket=ticket, attendant_id=attendant_id).first()
    if not cycle and create:
        cycle = TicketAttendantCycle.objects.create(ticket=ticket, attendant_id=attendant_id)
    return cycle


def _sync_ticket_cycle_snapshot(ticket: Ticket):
    """Keeps legacy field aligned with assigned attendant for compatibility."""
    started_at = None
    if ticket.assigned_to_id:
        cycle = _get_ticket_attendant_cycle(ticket, ticket.assigned_to_id, create=False)
        # Backward-compatibility: if legacy field still has an active cycle for
        # assigned attendant (old model), persist it into the per-attendant table.
        if not cycle and ticket.current_cycle_started_at:
            cycle = _get_ticket_attendant_cycle(ticket, ticket.assigned_to_id, create=True)
            if cycle and not cycle.current_cycle_started_at:
                cycle.current_cycle_started_at = ticket.current_cycle_started_at
                cycle.save(update_fields=['current_cycle_started_at', 'updated_at'])
        if cycle:
            started_at = cycle.current_cycle_started_at
        elif ticket.current_cycle_started_at:
            started_at = ticket.current_cycle_started_at
    if ticket.current_cycle_started_at != started_at:
        ticket.current_cycle_started_at = started_at
        ticket.save(update_fields=['current_cycle_started_at', 'updated_at'])


def _get_or_create_auth_user_for_erp(erp_user: ERPUser):
    username = (erp_user.username or '').strip()
    if not username:
        return None
    User = get_user_model()
    auth_user = User.objects.filter(username__iexact=username).first()
    primary_email_tokens = _split_email_tokens((erp_user.email or '').strip())
    primary_email = primary_email_tokens[0] if primary_email_tokens else ''
    if auth_user:
        changed_fields = []
        if primary_email and getattr(auth_user, 'email', '') != primary_email:
            auth_user.email = primary_email
            changed_fields.append('email')
        if hasattr(auth_user, 'is_active') and bool(getattr(auth_user, 'is_active', True)) != bool(erp_user.is_active):
            auth_user.is_active = bool(erp_user.is_active)
            changed_fields.append('is_active')
        if changed_fields:
            auth_user.save(update_fields=changed_fields)
        return auth_user

    create_kwargs = {'username': username}
    if hasattr(User, 'email'):
        create_kwargs['email'] = primary_email
    if hasattr(User, 'is_active'):
        create_kwargs['is_active'] = bool(erp_user.is_active)
    auth_user = User.objects.create(**create_kwargs)
    if hasattr(auth_user, 'set_unusable_password'):
        auth_user.set_unusable_password()
    full_name = (erp_user.full_name or '').strip()
    if full_name:
        parts = full_name.split()
        if hasattr(auth_user, 'first_name'):
            auth_user.first_name = parts[0]
        if hasattr(auth_user, 'last_name'):
            auth_user.last_name = ' '.join(parts[1:]) if len(parts) > 1 else ''
    auth_user.save()
    return auth_user


class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = 'core/dashboard.html'

    def get(self, request, *args, **kwargs):
        # A dashboard raiz ficou apenas como fallback; usuarios entram direto em Chamados.
        return redirect('chamados')

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
            return reverse('chamados')
        return reverse('chamados')


class UsersListView(LoginRequiredMixin, TemplateView):
    template_name = 'core/users_list.html'

    def post(self, request, *args, **kwargs):
        is_ti = is_ti_user(request)
        if not is_ti:
            messages.error(request, 'Apenas usuários do departamento TI podem importar do AD.')
            return self.get(request, *args, **kwargs)

        action = (request.POST.get('action') or '').strip().lower()
        if action == 'create_manual_user':
            full_name = (request.POST.get('full_name') or '').strip()
            username_raw = (request.POST.get('username') or '').strip()
            username = username_raw or None
            department = (request.POST.get('department') or '').strip()
            phone = (request.POST.get('phone') or '').strip()
            mobile = (request.POST.get('mobile') or '').strip()
            email_raw = (request.POST.get('email') or '').strip()
            email_tokens = _split_email_tokens(email_raw)
            email = email_tokens[0] if email_tokens else ''
            extension = (request.POST.get('extension') or '').strip()
            is_active = bool(request.POST.get('is_active'))

            if not full_name:
                messages.error(request, 'Informe o nome completo do usuário manual.')
                return self.get(request, *args, **kwargs)

            if username and ERPUser.objects.filter(username__iexact=username).exists():
                messages.error(request, 'Já existe um usuário com esse login.')
                return self.get(request, *args, **kwargs)

            user = ERPUser.objects.create(
                full_name=full_name,
                username=username,
                department=department,
                phone=phone,
                mobile=mobile,
                email=email,
                extension=extension,
                ad_guid=f'manual-{uuid4().hex}',
                is_active=is_active,
                is_email_user=is_active,
                is_manual=True,
            )
            for alias_email in email_tokens[1:]:
                EmailAlias.objects.get_or_create(user=user, email=alias_email)
            messages.success(request, f'Usuário manual cadastrado com sucesso: {full_name}.')
            return redirect('usuarios')

        if action == 'hide_user_from_list':
            user_id_raw = (request.POST.get('user_id') or '').strip()
            try:
                user_id = int(user_id_raw)
            except (TypeError, ValueError):
                messages.error(request, 'Usuário inválido para ocultar.')
                return redirect('usuarios')
            target = ERPUser.objects.filter(id=user_id).first()
            if not target:
                messages.error(request, 'Usuário não encontrado.')
                return redirect('usuarios')
            if target.is_hidden_from_users:
                messages.info(request, 'Usuário já está oculto da lista.')
                return redirect('usuarios')
            target.is_hidden_from_users = True
            target.save(update_fields=['is_hidden_from_users'])
            messages.success(request, f'Usuário ocultado da lista: {target.full_name}.')
            return redirect('usuarios')

        if action == 'unhide_user_from_list':
            user_id_raw = (request.POST.get('user_id') or '').strip()
            try:
                user_id = int(user_id_raw)
            except (TypeError, ValueError):
                messages.error(request, 'Usuário inválido para reativar na lista.')
                return redirect('usuarios')
            target = ERPUser.objects.filter(id=user_id).first()
            if not target:
                messages.error(request, 'Usuário não encontrado.')
                return redirect('usuarios')
            if not target.is_hidden_from_users:
                messages.info(request, 'Usuário já está visível na lista.')
                return redirect('usuarios')
            target.is_hidden_from_users = False
            target.save(update_fields=['is_hidden_from_users'])
            messages.success(request, f'Usuário reativado na lista: {target.full_name}.')
            return redirect('usuarios')

        if action == 'set_email_user_flag':
            user_id_raw = (request.POST.get('user_id') or '').strip()
            try:
                user_id = int(user_id_raw)
            except (TypeError, ValueError):
                messages.error(request, 'Usuário inválido para atualizar marcação de e-mail.')
                return redirect('usuarios')
            target = ERPUser.objects.filter(id=user_id).first()
            if not target:
                messages.error(request, 'Usuário não encontrado.')
                return redirect('usuarios')
            is_email_user = bool(request.POST.get('is_email_user'))
            if bool(target.is_email_user) != is_email_user:
                target.is_email_user = is_email_user
                target.save(update_fields=['is_email_user'])
            return redirect('usuarios')

        if action == 'update_emails_json':
            upload = request.FILES.get('emails_json')
            if not upload:
                messages.error(request, 'Selecione um arquivo JSON para atualizar os e-mails.')
                return redirect(f"{reverse('usuarios')}?tab=emails")

            try:
                payload = json.loads(upload.read().decode('utf-8-sig', errors='ignore'))
            except Exception:
                messages.error(request, 'Arquivo JSON inválido.')
                return redirect(f"{reverse('usuarios')}?tab=emails")

            first_key = 'First Name [Required]'
            last_key = 'Last Name [Required]'
            email_key = 'Email Address [Required]'
            last_login_key = 'Last Sign In [READ ONLY]'
            usage_key = 'Email Usage [READ ONLY]'

            rows = payload.get('users') if isinstance(payload, dict) else None
            if not isinstance(rows, list) or not rows:
                messages.error(request, 'JSON fora do padrão esperado. Estrutura esperada: {"users":[...]}')
                return redirect(f"{reverse('usuarios')}?tab=emails")
            first_row = rows[0] if isinstance(rows[0], dict) else {}
            if first_key not in first_row or last_key not in first_row or email_key not in first_row:
                messages.error(request, 'JSON fora do padrão esperado. Campos obrigatórios não encontrados.')
                return redirect(f"{reverse('usuarios')}?tab=emails")

            updated = 0
            unchanged = 0
            skipped = 0

            for row in rows:
                if not isinstance(row, dict):
                    skipped += 1
                    continue
                first = (row.get(first_key) or '').strip()
                last = (row.get(last_key) or '').strip()
                email = (row.get(email_key) or '').strip().lower()
                email_usage = (row.get(usage_key) or '').strip()
                last_sign_in = (row.get(last_login_key) or '').strip()
                status_raw = (row.get('Status [READ ONLY]') or '').strip()
                if not email:
                    skipped += 1
                    continue

                should_be_active = status_raw.lower() in {'active', 'ativado', 'enabled'}
                alias_candidates = []
                for key in ('Recovery Email', 'Home Secondary Email', 'Work Secondary Email'):
                    val = (row.get(key) or '').strip().lower()
                    if val and '@' in val:
                        alias_candidates.append(val)
                alias_candidates = sorted(
                    {
                        alias
                        for alias in alias_candidates
                        if alias and alias != email
                    }
                )
                alias_text = '; '.join(alias_candidates)
                full_name = f'{first} {last}'.strip()

                account, created = EmailAccount.objects.get_or_create(
                    email=email,
                    defaults={
                        'full_name': full_name,
                        'aliases': alias_text,
                        'email_usage': email_usage,
                        'email_last_sign_in': last_sign_in,
                        'status': status_raw,
                        'is_active': should_be_active,
                        'source': 'json',
                    },
                )
                if created:
                    updated += 1
                    continue

                changed = False
                if (account.full_name or '').strip() != full_name:
                    account.full_name = full_name
                    changed = True
                if (account.aliases or '').strip() != alias_text:
                    account.aliases = alias_text
                    changed = True
                if (account.email_usage or '').strip() != email_usage:
                    account.email_usage = email_usage
                    changed = True
                if (account.email_last_sign_in or '').strip() != last_sign_in:
                    account.email_last_sign_in = last_sign_in
                    changed = True
                if (account.status or '').strip() != status_raw:
                    account.status = status_raw
                    changed = True
                if bool(account.is_active) != bool(should_be_active):
                    account.is_active = should_be_active
                    changed = True
                if (account.source or '').strip() != 'json':
                    account.source = 'json'
                    changed = True
                if changed:
                    account.save()
                    updated += 1
                else:
                    unchanged += 1

            messages.success(request, f'Atualização de e-mails (JSON) concluída: {updated} atualizados, {unchanged} sem mudança, {skipped} ignorados.')
            return redirect(f"{reverse('usuarios')}?tab=emails")

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
        selected_tab = (self.request.GET.get('tab') or 'usuarios').strip().lower()
        if selected_tab not in {'usuarios', 'emails'}:
            selected_tab = 'usuarios'
        context['modules'] = build_modules(selected_tab) if is_ti else []
        show_inactive = self.request.GET.get('show_inactive') == '1'
        queryset = ERPUser.objects.filter(is_hidden_from_users=False)
        active_users = list(ERPUser.objects.filter(is_active=True, is_hidden_from_users=False))
        context['active_total_count'] = len(active_users)
        active_marked = [u for u in active_users if u.is_email_user]
        context['active_people_count'] = len(active_marked)
        context['active_non_people_count'] = max(0, len(active_users) - len(active_marked))
        if not show_inactive:
            queryset = queryset.filter(is_active=True)
        context['show_inactive'] = show_inactive
        context['users'] = queryset.order_by('full_name')
        context['hidden_users'] = ERPUser.objects.filter(is_hidden_from_users=True).order_by('full_name')
        email_accounts = list(EmailAccount.objects.all().order_by('full_name', 'email'))
        context['email_users'] = email_accounts
        context['email_unique_count'] = EmailAccount.objects.values('email').distinct().count()
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

        hostname = request.POST.get('hostname', '').strip()
        tag_code = request.POST.get('tag_code', '').strip()
        if not tag_code:
            tag_code = _infer_tag_code_from_hostname(hostname)

        equipment_payload = {
            'tag_code': tag_code,
            'sector': request.POST.get('sector', '').strip(),
            'user': request.POST.get('user', '').strip(),
            'hostname': hostname,
            'equipment': request.POST.get('equipment', '').strip(),
            'model': request.POST.get('model', '').strip(),
            'brand': request.POST.get('brand', '').strip(),
            'serial': request.POST.get('serial', '').strip(),
            'memory': request.POST.get('memory', '').strip(),
            'processor': request.POST.get('processor', '').strip(),
            'generation': request.POST.get('generation', '').strip(),
            'hd': request.POST.get('hd', '').strip(),
            'mod_hd': request.POST.get('mod_hd', '').strip(),
            'windows': request.POST.get('windows', '').strip(),
        }

        if action == 'update':
            equipment_id = (request.POST.get('equipment_id') or '').strip()
            equipment_obj = Equipment.objects.filter(id=equipment_id).first()
            if not equipment_obj:
                messages.error(request, 'Equipamento n?o encontrado para edi??o.')
                return self.get(request, *args, **kwargs)
            for field_name, field_value in equipment_payload.items():
                setattr(equipment_obj, field_name, field_value)
            equipment_obj.save()
            messages.success(request, 'Equipamento atualizado com sucesso.')
            return self.get(request, *args, **kwargs)

        Equipment.objects.create(**equipment_payload)
        messages.success(request, 'Equipamento cadastrado com sucesso.')
        return self.get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        is_ti = is_ti_user(self.request)
        context['is_ti_group'] = is_ti
        context['modules'] = build_modules('equipamentos') if is_ti else []
        equipments_qs = Equipment.objects.all().order_by('-created_at')
        context['equipments'] = equipments_qs
        context['equipment_total_count'] = equipments_qs.count()
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


class DicasView(LoginRequiredMixin, TemplateView):
    template_name = 'core/dicas.html'

    def post(self, request, *args, **kwargs):
        if not is_ti_user(request):
            messages.error(request, 'Apenas usuários do departamento TI podem gerenciar dicas.')
            return self.get(request, *args, **kwargs)

        action = (request.POST.get('action') or 'create').strip().lower()
        if action == 'delete':
            dica_id = (request.POST.get('dica_id') or '').strip()
            dica = Dica.objects.filter(id=dica_id).first()
            if not dica:
                messages.error(request, 'Dica não encontrada.')
                return redirect('dicas')
            if dica.attachment:
                dica.attachment.delete(save=False)
            dica.delete()
            messages.success(request, 'Dica removida com sucesso.')
            return redirect('dicas')

        title = (request.POST.get('title') or '').strip()
        content = (request.POST.get('content') or '').strip()
        attachment = request.FILES.get('attachment')
        category = (request.POST.get('category') or Dica.Category.GERAL).strip()
        valid_categories = {choice[0] for choice in Dica.Category.choices}
        if category not in valid_categories:
            category = Dica.Category.GERAL

        if not title:
            messages.error(request, 'Informe o título da dica.')
            return self.get(request, *args, **kwargs)
        if not content:
            messages.error(request, 'Informe a descrição da dica.')
            return self.get(request, *args, **kwargs)

        Dica.objects.create(
            category=category,
            title=title,
            content=content,
            attachment=attachment,
            created_by=request.user,
        )
        messages.success(request, 'Dica cadastrada com sucesso.')
        return redirect('dicas')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        is_ti = is_ti_user(self.request)
        context['is_ti_group'] = is_ti
        context['modules'] = build_modules('dicas') if is_ti else []
        context['dicas'] = Dica.objects.select_related('created_by').order_by('-updated_at', '-id') if is_ti else []
        context['dica_categories'] = Dica.Category.choices
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
        creator_user = request.user
        opened_at_dt = None

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
        else:
            requester_user_id = (request.POST.get('requester_user_id') or '').strip()
            opened_at_raw = (request.POST.get('opened_at') or '').strip()
            if requester_user_id:
                try:
                    requester_id = int(requester_user_id)
                except ValueError:
                    messages.error(request, 'Solicitante inválido.')
                    return self.get(request, *args, **kwargs)
                requester_erp_user = ERPUser.objects.filter(id=requester_id, is_active=True).first()
                if not requester_erp_user:
                    messages.error(request, 'Solicitante não encontrado.')
                    return self.get(request, *args, **kwargs)
                requester_auth_user = _get_or_create_auth_user_for_erp(requester_erp_user)
                if not requester_auth_user:
                    messages.error(request, 'Solicitante sem login válido para abertura.')
                    return self.get(request, *args, **kwargs)
                creator_user = requester_auth_user
            if opened_at_raw:
                try:
                    opened_at_dt = datetime.fromisoformat(opened_at_raw)
                    if timezone.is_naive(opened_at_dt):
                        opened_at_dt = timezone.make_aware(opened_at_dt, timezone.get_current_timezone())
                except ValueError:
                    messages.error(request, 'Data/hora de abertura inválida.')
                    return self.get(request, *args, **kwargs)

        recent_cutoff = timezone.now() - timedelta(seconds=30)
        duplicate = Ticket.objects.filter(
            created_by=creator_user,
            title=title,
            description=description,
            created_at__gte=recent_cutoff,
        ).exists()
        if duplicate:
            messages.info(request, 'Chamado idêntico detectado recentemente. Não foi criado novamente.')
            return redirect('chamados')

        initial_status = Ticket.Status.PENDENTE if is_ti else Ticket.Status.NOVO
        ticket = Ticket.objects.create(
            title=title,
            description=description,
            ticket_type=ticket_type,
            urgency=urgency,
            status=initial_status,
            created_by=creator_user,
            attachment=attachment,
        )
        if opened_at_dt:
            Ticket.objects.filter(id=ticket.id).update(created_at=opened_at_dt)
            ticket.created_at = opened_at_dt
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
        context['ti_opened_at_default'] = timezone.localtime(timezone.now()).strftime('%Y-%m-%dT%H:%M')
        if is_ti:
            context['ti_requesters'] = ERPUser.objects.filter(is_active=True).order_by('full_name', 'username')
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
        last_paths: dict[int, str] = {}
        ti_ids = [u.id for u in ti_users]
        if ti_ids:
            logs_with_path = (
                TicketWorkLog.objects.filter(attendant_id__in=ti_ids)
                .exclude(exported_path__isnull=True)
                .exclude(exported_path='')
                .order_by('attendant_id', '-exported_at', '-id')
                .values('attendant_id', 'exported_path')
            )
            for row in logs_with_path:
                aid = row.get('attendant_id')
                if aid in last_paths:
                    continue
                path_value = (row.get('exported_path') or '').strip()
                if path_value:
                    last_paths[aid] = path_value
        context['attendant_last_workbook_paths'] = last_paths
        context['new_tickets'] = (
            Ticket.objects.filter(
                status__in=[Ticket.Status.NOVO, Ticket.Status.PENDENTE, Ticket.Status.PROGRAMADO],
                assigned_to__isnull=True,
                collaborators__isnull=True,
            )
            .select_related('created_by')
            .annotate(
                queue_order=Case(
                    When(status=Ticket.Status.NOVO, then=Value(0)),
                    When(status=Ticket.Status.PENDENTE, then=Value(1)),
                    default=Value(2),
                    output_field=IntegerField(),
                )
            )
            .distinct()
            .order_by('queue_order', '-created_at')
        )
        context['closed_tickets'] = Ticket.objects.filter(status=Ticket.Status.FECHADO).select_related('created_by').order_by('-updated_at', '-id')
        in_progress_tickets = Ticket.objects.filter(
            status__in=[Ticket.Status.EM_ATENDIMENTO, Ticket.Status.PENDENTE]
        ).select_related('created_by').prefetch_related(
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
        for uid, tickets_for_user in ticket_map.items():
            ticket_map[uid] = sorted(
                tickets_for_user,
                key=lambda t: (
                    -(t.created_at.timestamp() if t.created_at else 0),
                ),
            )

        ticket_cycle_map: dict[int, dict[int, bool]] = {}
        in_progress_ids = [t.id for t in in_progress_tickets if t.id]
        if in_progress_ids:
            for cycle in TicketAttendantCycle.objects.filter(ticket_id__in=in_progress_ids).only(
                'ticket_id', 'attendant_id', 'current_cycle_started_at'
            ):
                if not cycle.current_cycle_started_at:
                    continue
                bucket = ticket_cycle_map.setdefault(cycle.ticket_id, {})
                bucket[cycle.attendant_id] = True
        for ticket in in_progress_tickets:
            if not ticket.current_cycle_started_at or not ticket.assigned_to_id:
                continue
            bucket = ticket_cycle_map.setdefault(ticket.id, {})
            bucket.setdefault(ticket.assigned_to_id, True)

        all_tickets = (
            list(context['new_tickets'])
            + list(context['closed_tickets'])
            + list(in_progress_tickets)
        )
        ticket_ids = list({t.id for t in all_tickets if t and t.id})
        latest_worklog_action_by_ticket: dict[int, str] = {}
        latest_timeline_note_by_ticket: dict[int, str] = {}
        latest_closed_at_by_ticket: dict[int, datetime] = {}
        latest_closed_by_name_by_ticket: dict[int, str] = {}
        if ticket_ids:
            timeline_rows = (
                TicketTimelineEvent.objects.filter(ticket_id__in=ticket_ids)
                .exclude(note='')
                .order_by('ticket_id', '-created_at', '-id')
                .values('ticket_id', 'note')
            )
            for row in timeline_rows:
                tid = row.get('ticket_id')
                if tid in latest_timeline_note_by_ticket:
                    continue
                note = (row.get('note') or '').strip()
                if note:
                    latest_timeline_note_by_ticket[tid] = note

            logs = (
                TicketWorkLog.objects.filter(ticket_id__in=ticket_ids)
                .order_by('ticket_id', '-closed_at', '-id')
                .values('ticket_id', 'action_text')
            )
            for row in logs:
                tid = row.get('ticket_id')
                if tid in latest_worklog_action_by_ticket:
                    continue
                latest_worklog_action_by_ticket[tid] = (row.get('action_text') or '').strip()

            closed_rows = (
                TicketTimelineEvent.objects.filter(ticket_id__in=ticket_ids, to_status=Ticket.Status.FECHADO)
                .order_by('ticket_id', '-created_at', '-id')
                .values('ticket_id', 'created_at', 'actor_ti__full_name', 'actor_user__username')
            )
            for row in closed_rows:
                tid = row.get('ticket_id')
                if tid in latest_closed_at_by_ticket:
                    continue
                closed_at = row.get('created_at')
                if closed_at:
                    latest_closed_at_by_ticket[tid] = closed_at
                actor_name = (row.get('actor_ti__full_name') or row.get('actor_user__username') or '').strip()
                if actor_name:
                    latest_closed_by_name_by_ticket[tid] = actor_name
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
                'last_action_text': latest_worklog_action_by_ticket.get(ticket.id, ''),
                'last_queue_action_text': latest_timeline_note_by_ticket.get(ticket.id, '') or latest_worklog_action_by_ticket.get(ticket.id, ''),
                'closed_at_text': timezone.localtime(latest_closed_at_by_ticket.get(ticket.id) or ticket.updated_at).strftime('%d/%m/%Y %H:%M') if (latest_closed_at_by_ticket.get(ticket.id) or ticket.updated_at) else '',
                'closed_by_text': latest_closed_by_name_by_ticket.get(ticket.id, ''),
            }
        context['ticket_meta'] = ticket_meta
        context['ticket_cycle_map'] = ticket_cycle_map

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
    unassign_only = request.POST.get('unassign_only') == '1'
    failure_type = _normalize_failure_type(request.POST.get('failure_type') or '')
    valid_failures = {choice[0] for choice in Ticket.FailureType.choices}
    if failure_type not in valid_failures:
        saved_failure = _normalize_failure_type(ticket.last_failure_type or '')
        if saved_failure in valid_failures:
            failure_type = saved_failure
    previous_status = ticket.status
    previous_assignee_id = ticket.assigned_to_id
    source_is_user = source_target.startswith('user_')
    source_user_id = _extract_source_user_id(source_target) if source_is_user else None
    source_cycle = _get_ticket_attendant_cycle(ticket, source_user_id, create=False) if source_user_id else None
    if (
        source_user_id
        and not source_cycle
        and ticket.current_cycle_started_at
        and ticket.assigned_to_id == source_user_id
    ):
        source_cycle = _get_ticket_attendant_cycle(ticket, source_user_id, create=True)
        if source_cycle and not source_cycle.current_cycle_started_at:
            source_cycle.current_cycle_started_at = ticket.current_cycle_started_at
            source_cycle.save(update_fields=['current_cycle_started_at', 'updated_at'])

    if target in {'novo', 'pendente', 'programado'}:
        destination_status = Ticket.Status.PENDENTE

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
                cycle_start = source_cycle.current_cycle_started_at if source_cycle and source_cycle.current_cycle_started_at else ticket.created_at
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
                if source_cycle and source_cycle.current_cycle_started_at:
                    source_cycle.current_cycle_started_at = None
                    source_cycle.save(update_fields=['current_cycle_started_at', 'updated_at'])
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
            _sync_ticket_cycle_snapshot(ticket)
            return JsonResponse({'ok': True, 'partial_unassign': True})

        if source_target.startswith('user_') and not progress_note:
            return JsonResponse({'ok': False, 'error': 'progress_note_required'}, status=400)
        if source_is_user:
            if failure_type not in valid_failures:
                return JsonResponse({'ok': False, 'error': 'failure_required'}, status=400)
            if not progress_note:
                return JsonResponse({'ok': False, 'error': 'action_required'}, status=400)
            if source_cycle and source_cycle.current_cycle_started_at:
                cycle_start = source_cycle.current_cycle_started_at
                closed_at = timezone.now()
                _create_ticket_work_log(
                    ticket=ticket,
                    source_target=source_target,
                    opened_at=cycle_start,
                    closed_at=closed_at,
                    failure_type=failure_type,
                    action_text=progress_note,
                )
                source_cycle.current_cycle_started_at = None
                source_cycle.save(update_fields=['current_cycle_started_at', 'updated_at'])

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
        _sync_ticket_cycle_snapshot(ticket)
        return JsonResponse({'ok': True})

    if target == 'fechado':
        if not source_is_user:
            return JsonResponse({'ok': False, 'error': 'close_only_from_attendant'}, status=400)
        if not resolution_note:
            return JsonResponse({'ok': False, 'error': 'resolution_required'}, status=400)
        if failure_type not in valid_failures:
            return JsonResponse({'ok': False, 'error': 'failure_required'}, status=400)
        if not source_cycle or not source_cycle.current_cycle_started_at:
            return JsonResponse({'ok': False, 'error': 'play_required'}, status=400)
        cycle_start = source_cycle.current_cycle_started_at
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
        source_cycle.current_cycle_started_at = None
        source_cycle.save(update_fields=['current_cycle_started_at', 'updated_at'])
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
        _sync_ticket_cycle_snapshot(ticket)
        return JsonResponse({'ok': True})

    if target.startswith('user_'):
        user_id = target.replace('user_', '')
        assignee = ERPUser.objects.filter(id=user_id).first()
        if not assignee:
            return JsonResponse({'ok': False, 'error': 'user_not_found'}, status=404)

        if unassign_only and source_is_user and source_user_id and source_user_id != assignee.id:
            current_assignees = set()
            if ticket.assigned_to_id:
                current_assignees.add(ticket.assigned_to_id)
            current_assignees.update(ticket.collaborators.values_list('id', flat=True))
            if source_user_id not in current_assignees or assignee.id not in current_assignees:
                return JsonResponse({'ok': False, 'error': 'invalid_source'}, status=400)
            if failure_type not in valid_failures:
                return JsonResponse({'ok': False, 'error': 'failure_required'}, status=400)
            if not progress_note:
                return JsonResponse({'ok': False, 'error': 'action_required'}, status=400)

            if source_cycle and source_cycle.current_cycle_started_at:
                cycle_start = source_cycle.current_cycle_started_at
                closed_at = timezone.now()
                _create_ticket_work_log(
                    ticket=ticket,
                    source_target=source_target,
                    opened_at=cycle_start,
                    closed_at=closed_at,
                    failure_type=failure_type,
                    action_text=progress_note,
                )
                source_cycle.current_cycle_started_at = None
                source_cycle.save(update_fields=['current_cycle_started_at', 'updated_at'])

            ticket.last_failure_type = failure_type
            if ticket.assigned_to_id == source_user_id:
                ticket.assigned_to_id = assignee.id
                ticket.save(update_fields=['assigned_to', 'last_failure_type', 'updated_at'])
                ticket.collaborators.remove(assignee.id)
            else:
                ticket.collaborators.remove(source_user_id)
                ticket.save(update_fields=['last_failure_type', 'updated_at'])

            _log_ticket_timeline(
                ticket=ticket,
                event_type=TicketTimelineEvent.EventType.UNASSIGNED,
                request_user=request.user,
                from_status=previous_status,
                to_status=ticket.status,
                note=f'Atendente removido do compartilhamento: {progress_note}',
            )
            _sync_ticket_cycle_snapshot(ticket)
            return JsonResponse({'ok': True, 'partial_unassign': True})

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
            if source_cycle and source_cycle.current_cycle_started_at:
                cycle_start = source_cycle.current_cycle_started_at
                closed_at = timezone.now()
                _create_ticket_work_log(
                    ticket=ticket,
                    source_target=source_target,
                    opened_at=cycle_start,
                    closed_at=closed_at,
                    failure_type=failure_type,
                    action_text=progress_note,
                )
                source_cycle.current_cycle_started_at = None
                source_cycle.save(update_fields=['current_cycle_started_at', 'updated_at'])

        if is_clone_assignment:
            ticket.save()
            ticket.collaborators.add(assignee)
            ticket.historical_attendants.add(assignee)
            timeline_note = f'{assignee.full_name} foi adicionado como colaborador no chamado.'
        else:
            ticket.assigned_to = assignee
            if was_closed:
                ticket.resolution = ''
            ticket.current_cycle_started_at = None
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
        _sync_ticket_cycle_snapshot(ticket)
        return JsonResponse({'ok': True})

    return JsonResponse({'ok': False, 'error': 'invalid_target'}, status=400)


@login_required
@require_POST
def ticket_timer_action(request):
    if not is_ti_user(request):
        return JsonResponse({'ok': False, 'error': 'forbidden'}, status=403)

    ticket_id = (request.POST.get('ticket_id') or '').strip()
    action = (request.POST.get('action') or '').strip().lower()
    source_target = (request.POST.get('source_target') or '').strip()
    action_note = (request.POST.get('action_note') or '').strip()
    failure_type = _normalize_failure_type(request.POST.get('failure_type') or '')
    valid_failures = {choice[0] for choice in Ticket.FailureType.choices}

    if not ticket_id or action not in {'play', 'pause'}:
        return JsonResponse({'ok': False, 'error': 'invalid'}, status=400)

    ticket = Ticket.objects.filter(id=ticket_id).first()
    if not ticket:
        return JsonResponse({'ok': False, 'error': 'not_found'}, status=404)
    if ticket.status not in {Ticket.Status.EM_ATENDIMENTO, Ticket.Status.PENDENTE}:
        return JsonResponse({'ok': False, 'error': 'not_in_progress'}, status=400)

    source_user_id = _extract_source_user_id(source_target)
    if not source_user_id:
        return JsonResponse({'ok': False, 'error': 'invalid_source'}, status=400)

    assignee_ids = set()
    if ticket.assigned_to_id:
        assignee_ids.add(ticket.assigned_to_id)
    assignee_ids.update(ticket.collaborators.values_list('id', flat=True))
    if source_user_id not in assignee_ids:
        return JsonResponse({'ok': False, 'error': 'invalid_source'}, status=400)

    source_cycle = _get_ticket_attendant_cycle(ticket, source_user_id, create=(action == 'play'))
    if not source_cycle:
        if ticket.current_cycle_started_at and ticket.assigned_to_id == source_user_id:
            source_cycle = _get_ticket_attendant_cycle(ticket, source_user_id, create=True)
            if source_cycle and not source_cycle.current_cycle_started_at:
                source_cycle.current_cycle_started_at = ticket.current_cycle_started_at
                source_cycle.save(update_fields=['current_cycle_started_at', 'updated_at'])
        if not source_cycle:
            return JsonResponse({'ok': False, 'error': 'invalid_source'}, status=400)

    if action == 'play':
        if source_cycle.current_cycle_started_at:
            return JsonResponse({'ok': True, 'running': True})
        previous_status = ticket.status
        source_cycle.current_cycle_started_at = timezone.now()
        source_cycle.save(update_fields=['current_cycle_started_at', 'updated_at'])
        if ticket.status != Ticket.Status.EM_ATENDIMENTO:
            ticket.status = Ticket.Status.EM_ATENDIMENTO
            ticket.save(update_fields=['status', 'updated_at'])
            _notify_whatsapp(
                ticket,
                event_type="status_in_progress",
                event_label="Status atualizado",
                extra_line="Status atual: Em atendimento",
            )
            _notify_ticket_email(
                ticket,
                event_label="Status atualizado",
                extra_line="Status atual: Em atendimento",
            )
        _sync_ticket_cycle_snapshot(ticket)
        _log_ticket_timeline(
            ticket=ticket,
            event_type=TicketTimelineEvent.EventType.STATUS_CHANGED,
            request_user=request.user,
            from_status=previous_status,
            to_status=ticket.status,
            note='Atendimento iniciado (Play).',
        )
        return JsonResponse({'ok': True, 'running': True, 'status': ticket.status})

    # pause
    if not source_cycle.current_cycle_started_at:
        return JsonResponse({'ok': False, 'error': 'not_running'}, status=400)
    if not action_note:
        return JsonResponse({'ok': False, 'error': 'action_required'}, status=400)
    if failure_type not in valid_failures:
        return JsonResponse({'ok': False, 'error': 'failure_required'}, status=400)

    closed_at = timezone.now()
    _create_ticket_work_log(
        ticket=ticket,
        source_target=source_target,
        opened_at=source_cycle.current_cycle_started_at,
        closed_at=closed_at,
        failure_type=failure_type,
        action_text=action_note,
    )
    source_cycle.current_cycle_started_at = None
    source_cycle.save(update_fields=['current_cycle_started_at', 'updated_at'])
    previous_status = ticket.status
    ticket.last_failure_type = failure_type
    has_running_cycles = TicketAttendantCycle.objects.filter(
        ticket=ticket,
        current_cycle_started_at__isnull=False,
    ).exists()
    if not has_running_cycles and ticket.status != Ticket.Status.FECHADO:
        ticket.status = Ticket.Status.PENDENTE
        ticket.save(update_fields=['last_failure_type', 'status', 'updated_at'])
        _notify_whatsapp(
            ticket,
            event_type="status_pending",
            event_label="Status atualizado",
            extra_line="Status atual: Pendente",
        )
        _notify_ticket_email(
            ticket,
            event_label="Status atualizado",
            extra_line="Status atual: Pendente",
        )
    else:
        ticket.save(update_fields=['last_failure_type', 'updated_at'])
    _sync_ticket_cycle_snapshot(ticket)
    _log_ticket_timeline(
        ticket=ticket,
        event_type=TicketTimelineEvent.EventType.STATUS_CHANGED,
        request_user=request.user,
        from_status=previous_status,
        to_status=ticket.status,
        note=f'Atendimento pausado (Pause): {action_note}',
    )
    return JsonResponse({'ok': True, 'running': False, 'failure_type': failure_type, 'status': ticket.status})


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

    can_edit = ticket.created_by_id == request.user.id
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
    if not export_path:
        messages.error(request, 'Informe o caminho da planilha.')
        return redirect('chamados')

    ok, exported_count, detail = export_attendant_logs_to_excel(
        attendant=attendant,
        workbook_path=export_path,
    )
    if ok:
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








