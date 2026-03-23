import logging
import json
import secrets
import mimetypes
import re
import unicodedata
import threading
from io import BytesIO
from uuid import uuid4
from textwrap import shorten
from decimal import Decimal, InvalidOperation
from pathlib import Path
import requests
from django.conf import settings
from django.contrib import messages
from django.core.mail import send_mail
from django.db import transaction
from django.db.models import Count, Q, Case, When, Value, IntegerField, Exists, OuterRef, Sum, Max
from django.db.models.functions import TruncDate
from django.shortcuts import redirect
from django.utils import timezone
from datetime import datetime, timedelta
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth import get_user_model
from django.http import JsonResponse, FileResponse, Http404, HttpResponse
from django.urls import reverse
from django.utils.dateparse import parse_date
from django.views.decorators.http import require_GET, require_POST
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import TemplateView
from django.contrib.auth import views as auth_views
from ldap3 import Connection, Server, SUBTREE
from ldap3.utils.conv import escape_filter_chars
from openpyxl import Workbook
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE

from .ldap_importer import import_ad_users
from .chamados_excel import export_attendant_logs_to_excel
from .models import (
    ERPUser,
    EmailAlias,
    EmailAccount,
    Equipment,
    SoftwareInventory,
    Insumo,
    Protocolo,
    next_equipment_tag_code,
    _extract_equipment_tag_number,
    Requisition,
    RequisitionQuote,
    RequisitionQuoteAttachment,
    RequisitionQuoteDiscount,
    AccessFolder,
    AccessMember,
    AuditLog,
    Dica,
    Responsibility,
    Pendencia,
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
)
from .audit import log_audit_event

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
    {'slug': 'atribuicoes', 'label': 'Atribuições', 'url_name': 'atribuicoes'},
    {'slug': 'acessos', 'label': 'Acessos', 'url_name': 'acessos'},
    {'slug': 'equipamentos', 'label': 'Equipamentos', 'url_name': 'equipamentos'},
    {'slug': 'ips', 'label': 'IPs', 'url_name': None},
    {'slug': 'emails', 'label': 'Emails', 'url_name': None},
    {'slug': 'ramais', 'label': 'Ramais', 'url_name': None},
    {'slug': 'softwares', 'label': 'Softwares', 'url_name': 'softwares'},
    {'slug': 'insumos', 'label': 'Insumos', 'url_name': 'insumos'},
    {'slug': 'protocolos', 'label': 'Protocolos', 'url_name': 'protocolos'},
    {'slug': 'requisicoes', 'label': 'Requisições', 'url_name': 'requisicoes'},
    {'slug': 'dicas', 'label': 'Dicas', 'url_name': 'dicas'},
    {'slug': 'emprestimos', 'label': 'Empréstimos', 'url_name': None},
    {'slug': 'relatorios', 'label': 'Relatórios', 'url_name': 'relatorios'},
    {'slug': 'auditoria', 'label': 'Auditoria', 'url_name': 'auditoria'},
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


def build_modules(active_slug: str | None, allowed_slugs: set[str] | None = None) -> list[dict[str, str | bool]]:
    allowed = set(allowed_slugs or [])
    modules = []
    for module in ERP_MODULES:
        if allowed and module['slug'] not in allowed:
            continue
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


def _resolve_app_version() -> tuple[str, str]:
    env_version = (getattr(settings, 'APP_VERSION', '') or '').strip()
    if env_version:
        return env_version, 'env'

    raw_marker = (getattr(settings, 'APP_VERSION_FILE', '.release-version') or '.release-version').strip()
    marker_path = Path(raw_marker)
    if not marker_path.is_absolute():
        marker_path = Path(settings.BASE_DIR) / marker_path

    if marker_path.exists():
        try:
            marker_content = marker_path.read_text(encoding='utf-8-sig').strip()
        except Exception:
            marker_content = ''
        if marker_content:
            return marker_content, 'file'
        try:
            stamp = datetime.fromtimestamp(marker_path.stat().st_mtime, tz=timezone.get_current_timezone())
            return stamp.strftime('%Y%m%d%H%M%S'), 'file-mtime'
        except Exception:
            pass

    return 'dev', 'fallback'


def _username_candidates(raw_username: str) -> list[str]:
    raw = (raw_username or '').strip()
    if not raw:
        return []
    candidates: list[str] = [raw]
    if '\\' in raw:
        tail = raw.rsplit('\\', 1)[-1].strip()
        if tail:
            candidates.append(tail)
    if '@' in raw:
        local = raw.split('@', 1)[0].strip()
        if local:
            candidates.append(local)
    uniq: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        uniq.append(item)
    return uniq


def _erp_user_from_request(request) -> ERPUser | None:
    username = getattr(getattr(request, 'user', None), 'username', '')
    candidates = _username_candidates(username)
    if not candidates:
        return None

    # Tenta primeiro correspondencia exata para evitar colisao por variacao de caixa.
    for candidate in candidates:
        exact = ERPUser.objects.filter(username=candidate).first()
        if exact:
            return exact

    # Fallback case-insensitive quando o cadastro nao estiver no mesmo formato.
    for candidate in candidates:
        fuzzy = ERPUser.objects.filter(username__iexact=candidate).order_by('id').first()
        if fuzzy:
            return fuzzy
    return None


def can_view_requisitions_readonly(request) -> bool:
    user = _erp_user_from_request(request)
    if not user:
        return False
    return bool(user.can_view_requisitions_readonly)


def can_decide_requisitions(request) -> bool:
    if is_ti_user(request):
        return True

    allowed_raw = getattr(settings, 'REQUISITIONS_DECISION_USERNAMES', ['isabel'])
    allowed: set[str] = set()
    if isinstance(allowed_raw, str):
        for token in allowed_raw.replace(';', ',').split(','):
            value = token.strip().lower()
            if value:
                allowed.add(value)
    elif isinstance(allowed_raw, (list, tuple, set)):
        for item in allowed_raw:
            value = str(item or '').strip().lower()
            if value:
                allowed.add(value)
    if not allowed:
        return False

    request_username = getattr(getattr(request, 'user', None), 'username', '')
    for candidate in _username_candidates(request_username):
        if candidate.lower() in allowed:
            return True

    erp_user = _erp_user_from_request(request)
    if erp_user:
        for candidate in _username_candidates(erp_user.username):
            if candidate.lower() in allowed:
                return True
    return False


def _inventory_default_hosts() -> str:
    return (getattr(settings, 'INVENTORY_DEFAULT_HOSTS', '') or '').strip()


def _inventory_agent_token() -> str:
    return (getattr(settings, 'INVENTORY_AGENT_TOKEN', '') or '').strip()


def _extract_inventory_agent_token(request) -> str:
    auth_header = (request.headers.get('Authorization') or '').strip()
    if auth_header.lower().startswith('bearer '):
        return auth_header[7:].strip()
    return (request.headers.get('X-Inventory-Token') or '').strip()


def _is_valid_inventory_agent_request(request) -> bool:
    expected = _inventory_agent_token()
    provided = _extract_inventory_agent_token(request)
    return bool(expected and provided and secrets.compare_digest(provided, expected))


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


def _upload_max_bytes() -> int:
    mb = int(getattr(settings, 'UPLOAD_MAX_FILE_MB', 10) or 10)
    return max(1, mb) * 1024 * 1024


def _allowed_upload_extensions() -> set[str]:
    values = getattr(settings, 'UPLOAD_ALLOWED_EXTENSIONS', []) or []
    normalized = {(item or '').strip().lower() for item in values}
    return {item if item.startswith('.') else f'.{item}' for item in normalized if item}


def _allowed_image_extensions() -> set[str]:
    values = getattr(settings, 'UPLOAD_ALLOWED_IMAGE_EXTENSIONS', []) or []
    normalized = {(item or '').strip().lower() for item in values}
    return {item if item.startswith('.') else f'.{item}' for item in normalized if item}


def _validate_upload(file_obj, *, image_only: bool = False) -> str:
    if not file_obj:
        return ''
    ext = Path(file_obj.name or '').suffix.lower()
    allowed_exts = _allowed_image_extensions() if image_only else _allowed_upload_extensions()
    if allowed_exts and ext not in allowed_exts:
        return f'Extensao de arquivo nao permitida: {ext or "(sem extensao)"}'
    if int(getattr(file_obj, 'size', 0) or 0) > _upload_max_bytes():
        max_mb = int(getattr(settings, 'UPLOAD_MAX_FILE_MB', 10) or 10)
        return f'Arquivo excede o limite de {max_mb}MB.'
    return ''


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
    try:
        summary = _build_whatsapp_summary(ticket, event_label=event_label, extra_line=extra_line)
    except Exception:
        logger.exception("Nao foi possivel montar mensagem WhatsApp do chamado %s", getattr(ticket, 'id', '?'))
        return

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
        except requests.Timeout as exc:
            logger.warning("Timeout ao notificar grupo WhatsApp %s: %s", group_jid, exc)
        except requests.RequestException as exc:
            logger.warning("Falha HTTP ao notificar grupo WhatsApp %s: %s", group_jid, exc)
        except Exception:
            logger.exception("Nao foi possivel notificar o grupo WhatsApp %s", group_jid)

    if send_individual:
        for phone in _get_attendant_numbers(ticket):
            try:
                send_whatsapp_message(phone, summary)
            except requests.Timeout as exc:
                logger.warning("Timeout ao notificar atendente %s: %s", phone, exc)
            except requests.RequestException as exc:
                logger.warning("Falha HTTP ao notificar atendente %s: %s", phone, exc)
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
    try:
        if 'nova mensagem' in label:
            subject = (templates.new_message_subject or DEFAULT_EMAIL_TEMPLATES['new_message_subject']).format_map(payload)
            body = (templates.new_message_body or DEFAULT_EMAIL_TEMPLATES['new_message_body']).format_map(payload)
        elif 'status atualizado' in label or 'atualizado' in label or 'em atendimento' in label:
            subject = (templates.status_update_subject or DEFAULT_EMAIL_TEMPLATES['status_update_subject']).format_map(payload)
            body = (templates.status_update_body or DEFAULT_EMAIL_TEMPLATES['status_update_body']).format_map(payload)
        else:
            subject = (templates.new_ticket_subject or DEFAULT_EMAIL_TEMPLATES['new_ticket_subject']).format_map(payload)
            body = (templates.new_ticket_body or DEFAULT_EMAIL_TEMPLATES['new_ticket_body']).format_map(payload)
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
    try:
        subject = (templates.new_ticket_subject or DEFAULT_EMAIL_TEMPLATES['new_ticket_subject']).format_map(payload)
        body = (templates.new_ticket_body or DEFAULT_EMAIL_TEMPLATES['new_ticket_body']).format_map(payload)
        send_mail(
            subject,
            body,
            settings.DEFAULT_FROM_EMAIL,
            recipients,
            fail_silently=False,
        )
    except Exception:
        logger.exception("Erro ao enviar e-mail de novo chamado para observadores: %s", ', '.join(recipients))


def _run_async_task(task_name: str, callback) -> None:
    def _runner():
        try:
            callback()
        except Exception:
            logger.exception("Falha inesperada na tarefa em background: %s", task_name)

    threading.Thread(
        target=_runner,
        name=f'erp-bg-{task_name}',
        daemon=True,
    ).start()


def _enqueue_new_ticket_notifications(ticket_id: int) -> None:
    def _notify_task():
        ticket = (
            Ticket.objects.filter(id=ticket_id)
            .select_related('created_by', 'assigned_to')
            .prefetch_related('collaborators')
            .first()
        )
        if not ticket:
            return
        try:
            _notify_whatsapp(ticket, event_type="new_ticket", event_label="Novo chamado")
        except Exception:
            logger.exception("Falha inesperada em notificacao WhatsApp do chamado %s", ticket_id)
        try:
            _notify_new_ticket_watchers_email(ticket)
        except Exception:
            logger.exception("Falha inesperada em notificacao por e-mail de observadores do chamado %s", ticket_id)

    transaction.on_commit(lambda: _run_async_task(f'new-ticket-notify-{ticket_id}', _notify_task))


def is_ti_user(request) -> bool:
    user = _erp_user_from_request(request)
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
    event_created_at=None,
):
    actor_ti = None
    username = getattr(request_user, 'username', '')
    if username:
        actor_ti = ERPUser.objects.filter(username__iexact=username).first()

    event = TicketTimelineEvent.objects.create(
        ticket=ticket,
        event_type=event_type,
        from_status=from_status or '',
        to_status=to_status or '',
        actor_user=request_user if getattr(request_user, 'is_authenticated', False) else None,
        actor_ti=actor_ti,
        note=(note or '').strip(),
    )
    if event_created_at:
        TicketTimelineEvent.objects.filter(id=event.id).update(created_at=event_created_at)


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

    def post(self, request, *args, **kwargs):
        try:
            return super().post(request, *args, **kwargs)
        except Exception:
            logger.exception('Falha inesperada no login para usuario=%s', (request.POST.get('username') or '').strip())
            messages.error(request, 'Falha temporaria ao entrar no sistema. Tente novamente em alguns segundos.')
            return redirect(request.get_full_path())

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
            return redirect(request.get_full_path())

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
                return redirect(request.get_full_path())

            if username and ERPUser.objects.filter(username__iexact=username).exists():
                messages.error(request, 'Já existe um usuário com esse login.')
                return redirect(request.get_full_path())

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

        if action == 'set_requisition_readonly_flag':
            user_id_raw = (request.POST.get('user_id') or '').strip()
            try:
                user_id = int(user_id_raw)
            except (TypeError, ValueError):
                messages.error(request, 'Usuário inválido para atualizar acesso de requisições.')
                return redirect('usuarios')
            target = ERPUser.objects.filter(id=user_id).first()
            if not target:
                messages.error(request, 'Usuário não encontrado.')
                return redirect('usuarios')
            allow_readonly = bool(request.POST.get('can_view_requisitions_readonly'))
            if bool(target.can_view_requisitions_readonly) != allow_readonly:
                target.can_view_requisitions_readonly = allow_readonly
                target.save(update_fields=['can_view_requisitions_readonly'])
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
        return redirect(request.get_full_path())

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
            return redirect(request.get_full_path())

        action = (request.POST.get('action') or '').strip().lower()
        if action == 'delete':
            messages.error(request, 'Exclusao de equipamentos bloqueada: a etiqueta nao pode ser removida.')
            return redirect(request.get_full_path())

        if action == 'reconcile_inventory':
            pending_id = (request.POST.get('pending_equipment_id') or '').strip()
            target_tag = (request.POST.get('target_tag_code') or '').strip()
            pending = Equipment.objects.filter(id=pending_id).first()
            if not pending:
                messages.error(request, 'Equipamento pendente n?o encontrado.')
                return redirect(request.get_full_path())
            if not target_tag:
                messages.error(request, 'Informe a etiqueta correta para vincular o invent?rio.')
                return redirect(request.get_full_path())

            if target_tag == (pending.tag_code or '').strip():
                pending.needs_reconciliation = False
                pending.save(update_fields=['needs_reconciliation'])
                messages.success(request, f'Invent?rio da etiqueta {target_tag} confirmado.')
                return redirect(request.get_full_path())

            target = Equipment.objects.filter(tag_code=target_tag).exclude(id=pending.id).first()
            if not target:
                messages.error(request, f'Etiqueta {target_tag} n?o encontrada para vincula??o.')
                return redirect(request.get_full_path())

            def _split_lines(raw_text: str) -> list[str]:
                items: list[str] = []
                for line in (raw_text or '').replace(';', '\n').splitlines():
                    token = line.strip()
                    if token and token not in items:
                        items.append(token)
                return items

            def _merge_lines(a: str, b: str) -> str:
                merged: list[str] = []
                for token in _split_lines(a) + _split_lines(b):
                    if token and token not in merged:
                        merged.append(token)
                return '\n'.join(merged)

            with transaction.atomic():
                old_target_hostname = (target.hostname or '').strip()
                pending_hostname = (pending.hostname or '').strip()

                # campos t?cnicos e de invent?rio v?m do pendente (GPO)
                for field_name in [
                    'hostname', 'sector', 'user', 'model', 'brand', 'serial',
                    'bios_uuid', 'bios_serial', 'baseboard_serial',
                    'memory', 'processor', 'generation', 'hd', 'mod_hd', 'windows',
                    'inventory_source', 'last_inventory_at',
                ]:
                    value = getattr(pending, field_name)
                    if value not in (None, ''):
                        setattr(target, field_name, value)

                for field_name in ['equipment', 'alimentacao']:
                    target_value = (getattr(target, field_name) or '').strip()
                    pending_value = (getattr(pending, field_name) or '').strip()
                    if not target_value and pending_value:
                        setattr(target, field_name, pending_value)
                target.observacao = _merge_lines(target.observacao, pending.observacao)

                target.mac_addresses = _merge_lines(target.mac_addresses, pending.mac_addresses)
                target.hostname_aliases = _merge_lines(target.hostname_aliases, pending.hostname_aliases)
                if old_target_hostname and old_target_hostname != (target.hostname or '').strip():
                    target.hostname_aliases = _merge_lines(target.hostname_aliases, old_target_hostname)
                if pending_hostname and pending_hostname != (target.hostname or '').strip():
                    target.hostname_aliases = _merge_lines(target.hostname_aliases, pending_hostname)
                target.needs_reconciliation = False
                target.save()

                SoftwareInventory.objects.filter(equipment=target).delete()
                SoftwareInventory.objects.filter(equipment=pending).update(
                    equipment=target,
                    hostname=target.hostname or pending.hostname,
                    user=target.user or pending.user,
                    sector=target.sector or pending.sector,
                )
                pending.delete()

            messages.success(request, f'Invent?rio vinculado ? etiqueta {target_tag} com sucesso.')
            return redirect(request.get_full_path())

        if action == 'sync_inventory':
            hosts_text = (request.POST.get('inventory_hosts') or '').strip()
            hosts = parse_hosts_text(hosts_text) or parse_hosts_text(_inventory_default_hosts())
            if not hosts:
                messages.error(request, 'Informe pelo menos um host para inventariar (ex.: PC01,PC02).')
                return redirect(request.get_full_path())
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
            return redirect(request.get_full_path())

        hostname = request.POST.get('hostname', '').strip()

        equipment_payload = {
            'tag_code': (request.POST.get('tag_code') or '').strip(),
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
            'alimentacao': request.POST.get('alimentacao', '').strip(),
            'observacao': request.POST.get('observacao', '').strip(),
        }

        if action == 'update':
            equipment_id = (request.POST.get('equipment_id') or '').strip()
            equipment_obj = Equipment.objects.filter(id=equipment_id).first()
            original_tag_code = (equipment_obj.tag_code or '').strip() if equipment_obj else ''
            if not equipment_obj:
                messages.error(request, 'Equipamento n?o encontrado para edi??o.')
                return redirect(request.get_full_path())
            for field_name, field_value in equipment_payload.items():
                setattr(equipment_obj, field_name, field_value)
            equipment_obj.tag_code = original_tag_code or (equipment_obj.tag_code or '').strip() or next_equipment_tag_code()
            equipment_obj.save()
            messages.success(request, 'Equipamento atualizado com sucesso.')
            return redirect(request.get_full_path())

        equipment_payload['tag_code'] = (equipment_payload.get('tag_code') or '').strip() or next_equipment_tag_code()
        Equipment.objects.create(**equipment_payload)
        messages.success(request, 'Equipamento cadastrado com sucesso.')
        return redirect(request.get_full_path())

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        is_ti = is_ti_user(self.request)
        context['is_ti_group'] = is_ti
        context['modules'] = build_modules('equipamentos') if is_ti else []
        equipments_qs = sorted(
            Equipment.objects.filter(needs_reconciliation=False),
            key=lambda e: (
                _extract_equipment_tag_number(e.tag_code or '') is None,
                _extract_equipment_tag_number(e.tag_code or '') or 10**9,
                (e.tag_code or '').lower(),
                e.id,
            ),
        )
        context['equipments'] = equipments_qs
        context['equipment_total_count'] = len(equipments_qs)
        context['inventory_default_hosts'] = _inventory_default_hosts()
        context['inventory_timeout_seconds'] = int(getattr(settings, 'INVENTORY_POWERSHELL_TIMEOUT', 120) or 120)
        context['next_equipment_tag_preview'] = next_equipment_tag_code() if is_ti else ''
        if is_ti:
            pending_items = list(Equipment.objects.filter(needs_reconciliation=True).order_by('-last_inventory_at', '-created_at'))
            erp_map: dict[str, ERPUser] = {}
            for erp_user in ERPUser.objects.exclude(username__isnull=True).exclude(username='').only(
                'username',
                'full_name',
                'department',
            ):
                key = (erp_user.username or '').strip().lower()
                if key and key not in erp_map:
                    erp_map[key] = erp_user

            for pending in pending_items:
                login = (pending.user or '').strip()
                erp_user = erp_map.get(login.lower()) if login else None
                pending.logged_user_login = login
                pending.logged_user_name = (erp_user.full_name or '').strip() if erp_user else ''
                pending.logged_user_department = (erp_user.department or '').strip() if erp_user else ''

            context['equipment_reconciliation_pending'] = pending_items
        else:
            context['equipment_reconciliation_pending'] = Equipment.objects.none()
        return context


class SoftwaresView(LoginRequiredMixin, TemplateView):
    template_name = 'core/softwares.html'

    @staticmethod
    def _base_queryset():
        return SoftwareInventory.objects.select_related('equipment').order_by(
            '-collected_at', '-updated_at', 'hostname', 'software_name'
        )

    @staticmethod
    def _apply_search(queryset, search_raw: str):
        term = (search_raw or '').strip()
        if not term:
            return queryset
        return queryset.filter(
            Q(hostname__icontains=term)
            | Q(sector__icontains=term)
            | Q(user__icontains=term)
            | Q(software_name__icontains=term)
            | Q(version__icontains=term)
            | Q(vendor__icontains=term)
            | Q(software_serial__icontains=term)
            | Q(install_date__icontains=term)
            | Q(equipment__serial__icontains=term)
        )

    @staticmethod
    def _excel_safe(value):
        text = str(value or '-')
        return ILLEGAL_CHARACTERS_RE.sub('', text)

    def _export_excel(self, search_raw: str):
        items = list(self._apply_search(self._base_queryset(), search_raw))

        wb = Workbook()
        ws = wb.active
        ws.title = 'Softwares'
        ws.append(
            [
                'Host',
                'Setor',
                'Usuario',
                'Serial Equipamento',
                'Serial Software',
                'Software',
                'Versao',
                'Fornecedor',
                'Instalacao',
                'Coletado em',
            ]
        )

        for item in items:
            collected_at = timezone.localtime(item.collected_at).strftime('%d/%m/%Y %H:%M') if item.collected_at else '-'
            ws.append(
                [
                    self._excel_safe(item.hostname),
                    self._excel_safe(item.sector),
                    self._excel_safe(item.user),
                    self._excel_safe(item.equipment.serial if item.equipment else ''),
                    self._excel_safe(item.software_serial),
                    self._excel_safe(item.software_name),
                    self._excel_safe(item.version),
                    self._excel_safe(item.vendor),
                    self._excel_safe(item.install_date),
                    self._excel_safe(collected_at),
                ]
            )

        output = BytesIO()
        wb.save(output)
        output.seek(0)

        stamp = timezone.localtime(timezone.now()).strftime('%Y%m%d_%H%M%S')
        suffix = 'pesquisa' if (search_raw or '').strip() else 'todos'
        filename = f'softwares_{suffix}_{stamp}.xlsx'
        response = HttpResponse(
            output.getvalue(),
            content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        )
        response['Content-Disposition'] = f'attachment; filename=\"{filename}\"'
        return response

    def post(self, request, *args, **kwargs):
        if not is_ti_user(request):
            messages.error(request, 'Apenas usuários do departamento TI podem atualizar inventário de software.')
            return redirect(request.get_full_path())

        action = (request.POST.get('action') or '').strip().lower()
        if action != 'sync_inventory':
            return redirect(request.get_full_path())

        hosts_text = (request.POST.get('inventory_hosts') or '').strip()
        hosts = parse_hosts_text(hosts_text) or parse_hosts_text(_inventory_default_hosts())
        if not hosts:
            messages.error(request, 'Informe pelo menos um host para inventariar (ex.: PC01,PC02).')
            return redirect(request.get_full_path())

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
        return redirect(request.get_full_path())

    def get(self, request, *args, **kwargs):
        if not is_ti_user(request):
            return super().get(request, *args, **kwargs)
        search_raw = (request.GET.get('q') or '').strip()
        export_flag = (request.GET.get('export') or '').strip().lower()
        if export_flag in {'1', 'true', 'xlsx'}:
            return self._export_excel(search_raw)
        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        is_ti = is_ti_user(self.request)
        context['is_ti_group'] = is_ti
        context['modules'] = build_modules('softwares') if is_ti else []
        search_raw = (self.request.GET.get('q') or '').strip()
        base_qs = self._base_queryset()
        filtered_qs = self._apply_search(base_qs, search_raw)
        context['software_items'] = filtered_qs
        context['software_search'] = search_raw
        context['software_total_count'] = base_qs.count()
        context['software_filtered_count'] = filtered_qs.count()
        context['inventory_default_hosts'] = _inventory_default_hosts()
        context['inventory_timeout_seconds'] = int(getattr(settings, 'INVENTORY_POWERSHELL_TIMEOUT', 120) or 120)
        return context


class InsumosView(LoginRequiredMixin, TemplateView):
    template_name = 'core/insumos.html'
    STOCK_CREATE_DEPARTMENT = 'Cadastro de estoque'
    STOCK_IN_PREFIX = 'Entrada:'
    STOCK_OUT_PREFIX = 'Saida:'

    @staticmethod
    def _normalize_item_name(raw_value: str) -> str:
        return re.sub(r'\s+', ' ', (raw_value or '').strip())

    @classmethod
    def _stock_movement_q(cls):
        return (
            Q(department=cls.STOCK_CREATE_DEPARTMENT)
            | Q(department__startswith=cls.STOCK_IN_PREFIX)
            | Q(department__startswith=cls.STOCK_OUT_PREFIX)
        )

    @classmethod
    def _stock_movements_queryset(cls):
        return Insumo.objects.filter(cls._stock_movement_q())

    @classmethod
    def _stock_snapshot(cls) -> dict[str, dict[str, Decimal | str]]:
        snapshot: dict[str, dict[str, Decimal | str]] = {}
        for row in cls._stock_movements_queryset().only('item', 'quantity').order_by('item', 'id'):
            item_name = cls._normalize_item_name(row.item)
            if not item_name:
                continue
            key = item_name.casefold()
            if key not in snapshot:
                snapshot[key] = {'item': item_name, 'quantity': Decimal('0')}
            snapshot[key]['quantity'] = Decimal(snapshot[key]['quantity']) + Decimal(row.quantity or 0)
        return snapshot

    @classmethod
    def _stock_rows(cls) -> list[dict[str, Decimal | str]]:
        rows = list(cls._stock_snapshot().values())
        rows.sort(key=lambda row: str(row['item']).casefold())
        return rows

    @staticmethod
    def _parse_decimal_br(raw_value: str, *, allow_negative: bool = False) -> Decimal:
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
        if value == 0:
            raise InvalidOperation
        if value < 0 and not allow_negative:
            raise InvalidOperation
        return value

    def post(self, request, *args, **kwargs):
        if not is_ti_user(request):
            messages.error(request, 'Apenas usuários do departamento TI podem cadastrar insumos.')
            return redirect(request.get_full_path())

        mode = (request.POST.get('mode') or 'create').strip().lower()

        if mode == 'stock_create':
            stock_item = self._normalize_item_name(request.POST.get('stock_item') or request.POST.get('item'))
            stock_quantity_raw = (request.POST.get('stock_quantity') or request.POST.get('quantity') or '').strip()
            if not stock_item:
                messages.error(request, 'Informe o nome do insumo para cadastrar no estoque.')
                return redirect('insumos')
            try:
                stock_quantity = self._parse_decimal_br(stock_quantity_raw)
            except (InvalidOperation, ValueError):
                messages.error(request, 'Quantidade invalida. Ex.: 1,00')
                return redirect('insumos')
            Insumo.objects.create(
                item=stock_item,
                date=timezone.localdate(),
                quantity=stock_quantity,
                name='Estoque',
                department=self.STOCK_CREATE_DEPARTMENT,
            )
            messages.success(request, f'Estoque de "{stock_item}" cadastrado com sucesso.')
            return redirect('insumos')

        if mode == 'stock_delete':
            stock_item = self._normalize_item_name(request.POST.get('stock_item') or request.POST.get('item'))
            if not stock_item:
                messages.error(request, 'Informe o insumo para apagar do estoque.')
                return redirect('insumos')
            normalized_key = stock_item.casefold()
            ids_to_delete = []
            for row in self._stock_movements_queryset().only('id', 'item'):
                if self._normalize_item_name(row.item).casefold() == normalized_key:
                    ids_to_delete.append(row.id)
            if not ids_to_delete:
                messages.error(request, f'Item "{stock_item}" nao encontrado no estoque.')
                return redirect('insumos')
            deleted_count, _ = Insumo.objects.filter(id__in=ids_to_delete).delete()
            if deleted_count <= 0:
                messages.error(request, f'Nao foi possivel apagar "{stock_item}" do estoque.')
                return redirect('insumos')
            messages.success(request, f'Estoque de "{stock_item}" apagado com sucesso.')
            return redirect('insumos')

        if mode == 'stock_adjust':
            stock_item = self._normalize_item_name(request.POST.get('stock_item') or request.POST.get('item'))
            stock_direction = (request.POST.get('stock_direction') or '').strip().lower()
            stock_quantity_raw = (request.POST.get('stock_quantity') or request.POST.get('quantity') or '').strip()
            stock_target = (request.POST.get('stock_target') or request.POST.get('name') or '').strip()
            stock_reason = (request.POST.get('stock_reason') or '').strip()

            if not stock_item:
                messages.error(request, 'Informe o insumo.')
                return redirect('insumos')
            if stock_direction not in {'inc', 'dec'}:
                messages.error(request, 'Movimentacao invalida.')
                return redirect('insumos')
            if not stock_target:
                messages.error(request, 'Informe para quem foi o insumo.')
                return redirect('insumos')
            if not stock_reason:
                messages.error(request, 'Informe o motivo da movimentacao.')
                return redirect('insumos')

            try:
                stock_quantity = self._parse_decimal_br(stock_quantity_raw)
            except (InvalidOperation, ValueError):
                messages.error(request, 'Quantidade invalida. Ex.: 1,00')
                return redirect('insumos')

            movement_quantity = stock_quantity
            if stock_direction == 'dec':
                current_qty = Decimal(self._stock_snapshot().get(stock_item.casefold(), {}).get('quantity') or 0)
                if current_qty < stock_quantity:
                    current_text = f'{current_qty:.2f}'.replace('.', ',')
                    messages.error(request, f'Estoque insuficiente de "{stock_item}". Atual: {current_text}')
                    return redirect('insumos')
                movement_quantity = -stock_quantity

            direction_label = 'Entrada' if stock_direction == 'inc' else 'Saida'
            department_value = f'{direction_label}: {stock_reason}'
            Insumo.objects.create(
                item=stock_item,
                date=timezone.localdate(),
                quantity=movement_quantity,
                name=stock_target[:200],
                department=department_value[:120],
            )

            if stock_direction == 'dec':
                Insumo.objects.create(
                    item=stock_item,
                    date=timezone.localdate(),
                    quantity=stock_quantity,
                    name=stock_target[:200],
                    department=stock_reason[:120],
                )
            messages.success(request, 'Movimentacao de estoque registrada com sucesso.')
            return redirect('insumos')

        insumo_id = (request.POST.get('insumo_id') or '').strip()
        item = self._normalize_item_name(request.POST.get('item') or '')
        date_raw = (request.POST.get('date') or '').strip()
        quantity_raw = (request.POST.get('quantity') or '').strip()
        name = (request.POST.get('name') or '').strip()
        department = (request.POST.get('department') or '').strip()

        if not item:
            messages.error(request, 'Informe o insumo.')
            return redirect(request.get_full_path())
        if not date_raw:
            messages.error(request, 'Informe a data.')
            return redirect(request.get_full_path())
        if not name:
            messages.error(request, 'Informe o nome.')
            return redirect(request.get_full_path())

        try:
            entry_date = datetime.strptime(date_raw, '%Y-%m-%d').date()
        except ValueError:
            messages.error(request, 'Data inválida.')
            return redirect(request.get_full_path())

        try:
            quantity = self._parse_decimal_br(quantity_raw, allow_negative=(mode == 'update'))
        except (InvalidOperation, ValueError):
            messages.error(request, 'Quantidade inválida. Ex.: 1,00')
            return redirect(request.get_full_path())

        if mode == 'update':
            insumo = Insumo.objects.filter(id=insumo_id).first()
            if not insumo:
                messages.error(request, 'Registro de insumo não encontrado para edição.')
                return redirect('insumos')
            insumo.item = item
            insumo.date = entry_date
            insumo.quantity = quantity
            insumo.name = name
            insumo.department = department
            insumo.save(update_fields=['item', 'date', 'quantity', 'name', 'department'])
            messages.success(request, 'Insumo atualizado com sucesso.')
            return redirect('insumos')

        Insumo.objects.create(
            item=item,
            date=entry_date,
            quantity=quantity,
            name=name,
            department=department,
        )
        messages.success(request, 'Insumo cadastrado com sucesso.')
        return redirect('insumos')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        is_ti = is_ti_user(self.request)
        context['is_ti_group'] = is_ti
        context['modules'] = build_modules('insumos') if is_ti else []
        context['insumos'] = Insumo.objects.exclude(self._stock_movement_q()).order_by('-date', '-id') if is_ti else []
        context['estoque_atual'] = self._stock_rows() if is_ti else []
        context['insumo_default_date'] = timezone.localdate().isoformat()
        return context


class ProtocolosView(LoginRequiredMixin, TemplateView):
    template_name = 'core/protocolos.html'

    @staticmethod
    def _parse_created_at(value: str):
        raw = (value or '').strip()
        if not raw:
            return timezone.localtime(timezone.now()).replace(second=0, microsecond=0)
        try:
            dt_value = datetime.fromisoformat(raw)
        except ValueError:
            return None
        if timezone.is_naive(dt_value):
            dt_value = timezone.make_aware(dt_value, timezone.get_current_timezone())
        return dt_value

    def post(self, request, *args, **kwargs):
        if not is_ti_user(request):
            messages.error(request, 'Apenas usuários do departamento TI podem cadastrar protocolos.')
            return redirect(request.get_full_path())

        mode = (request.POST.get('mode') or 'create').strip().lower()
        protocolo_id = (request.POST.get('protocolo_id') or '').strip()
        nome = (request.POST.get('nome') or '').strip()
        protocolo = (request.POST.get('protocolo') or '').strip()
        os_value = (request.POST.get('os') or '').strip()
        observacao = (request.POST.get('observacao') or '').strip()
        created_at_raw = (request.POST.get('created_at') or '').strip()
        created_at_dt = self._parse_created_at(created_at_raw)

        if not nome:
            messages.error(request, 'Informe o nome.')
            return redirect(request.get_full_path())
        if not protocolo:
            messages.error(request, 'Informe o protocolo.')
            return redirect(request.get_full_path())
        if not os_value:
            messages.error(request, 'Informe a OS.')
            return redirect(request.get_full_path())
        if created_at_dt is None:
            messages.error(request, 'Informe uma data/hora válida.')
            return redirect(request.get_full_path())

        if mode == 'update':
            protocolo_obj = Protocolo.objects.filter(id=protocolo_id).first()
            if not protocolo_obj:
                messages.error(request, 'Registro de protocolo não encontrado para edição.')
                return redirect('protocolos')
            protocolo_obj.nome = nome
            protocolo_obj.protocolo = protocolo
            protocolo_obj.os = os_value
            protocolo_obj.observacao = observacao
            protocolo_obj.created_at = created_at_dt
            protocolo_obj.save(update_fields=['nome', 'protocolo', 'os', 'observacao', 'created_at', 'updated_at'])
            messages.success(request, 'Protocolo atualizado com sucesso.')
            return redirect('protocolos')

        protocolo_obj = Protocolo.objects.create(
            nome=nome,
            protocolo=protocolo,
            os=os_value,
            observacao=observacao,
        )
        Protocolo.objects.filter(id=protocolo_obj.id).update(created_at=created_at_dt)
        messages.success(request, 'Protocolo cadastrado com sucesso.')
        return redirect('protocolos')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        is_ti = is_ti_user(self.request)
        context['is_ti_group'] = is_ti
        context['modules'] = build_modules('protocolos') if is_ti else []
        context['protocolos'] = Protocolo.objects.all().order_by('-id') if is_ti else []
        return context


class RequisicoesView(LoginRequiredMixin, TemplateView):
    template_name = 'core/requisicoes.html'

    @staticmethod
    def _excel_safe(value):
        text = str(value or '-')
        return ILLEGAL_CHARACTERS_RE.sub('', text)

    @staticmethod
    def _normalize_text(value: str) -> str:
        return (value or '').strip().lower()

    def _filter_requisitions_for_export(self, requisitions, search_raw: str, status_raw: str):
        query = self._normalize_text(search_raw)
        status = self._normalize_text(status_raw)
        filtered = []
        for req in requisitions:
            if status and self._normalize_text(req.status) != status:
                continue

            if query:
                quote_names = ' '.join((quote.name or '') for quote in getattr(req, 'main_quotes', [])).strip()
                haystack = ' '.join(
                    [
                        req.code or '',
                        req.title or '',
                        req.request or '',
                        getattr(req, 'kind_display', '') or '',
                        req.get_status_display() if hasattr(req, 'get_status_display') else '',
                        req.status or '',
                        quote_names,
                    ]
                )
                if query not in self._normalize_text(haystack):
                    continue

            filtered.append(req)
        return filtered

    def _export_excel(self, requisitions, search_raw: str = '', status_raw: str = ''):
        items = self._filter_requisitions_for_export(list(requisitions), search_raw, status_raw)

        wb = Workbook()
        ws = wb.active
        ws.title = 'Requisicoes'
        ws.append(
            [
                'ID',
                'Codigo',
                'Titulo',
                'Requisicao',
                'Tipo',
                'Status',
                'Orcamentos',
                'Suborcamentos',
                'Total aprovado',
                'Qtd esperada',
                'Qtd entregue',
                'Qtd pendente',
                'Data pedido',
                'Data aprovacao',
                'Data entrega parcial',
                'Data entrega total',
                'Orcamento(s) aprovado(s)',
            ]
        )

        for req in items:
            approved_quotes = [
                quote.name
                for quote in getattr(req, 'main_quotes', [])
                if quote.id in getattr(req, 'approved_quote_ids', set())
            ]
            requested_at = req.requested_at or (req.created_at.date() if req.created_at else None)
            ws.append(
                [
                    req.id,
                    self._excel_safe(req.code),
                    self._excel_safe(req.title),
                    self._excel_safe(req.request),
                    self._excel_safe(getattr(req, 'kind_display', '') or '-'),
                    self._excel_safe(req.get_status_display() if hasattr(req, 'get_status_display') else req.status),
                    int(getattr(req, 'main_quotes_count', 0) or 0),
                    int(getattr(req, 'sub_quotes_count', 0) or 0),
                    float(req.quotes_total) if getattr(req, 'quotes_total', None) is not None else '',
                    int(getattr(req, 'expected_delivery_quantity', 0) or 0),
                    int(getattr(req, 'delivered_quantity_display', 0) or 0),
                    int(getattr(req, 'pending_delivery_quantity', 0) or 0),
                    requested_at.strftime('%d/%m/%Y') if requested_at else '',
                    req.approved_at.strftime('%d/%m/%Y') if req.approved_at else '',
                    req.partially_received_at.strftime('%d/%m/%Y') if req.partially_received_at else '',
                    req.received_at.strftime('%d/%m/%Y') if req.received_at else '',
                    self._excel_safe(', '.join([name for name in approved_quotes if name])),
                ]
            )

        output = BytesIO()
        wb.save(output)
        output.seek(0)

        stamp = timezone.localtime(timezone.now()).strftime('%Y%m%d_%H%M%S')
        has_filter = bool((search_raw or '').strip() or (status_raw or '').strip())
        suffix = 'filtro' if has_filter else 'todos'
        filename = f'requisicoes_{suffix}_{stamp}.xlsx'
        response = HttpResponse(
            output.getvalue(),
            content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        )
        response['Content-Disposition'] = f'attachment; filename=\"{filename}\"'
        return response

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

    def _parse_price_history_payload(self, raw_json: str, idx: str) -> tuple[list[dict], str | None]:
        raw = (raw_json or '').strip()
        if not raw:
            return [], None
        try:
            parsed = json.loads(raw)
        except (TypeError, ValueError, json.JSONDecodeError):
            return [], f'Orçamento #{idx}: histórico de preço inválido.'
        if not isinstance(parsed, list):
            return [], f'Orçamento #{idx}: histórico de preço inválido.'

        normalized_items: list[dict] = []
        for entry in parsed:
            if not isinstance(entry, dict):
                continue
            previous_raw = entry.get('previous_value')
            updated_raw = entry.get('updated_value')
            if previous_raw in (None, '') or updated_raw in (None, ''):
                continue
            try:
                previous_value = self._parse_decimal_br(str(previous_raw))
                updated_value = self._parse_decimal_br(str(updated_raw))
            except (InvalidOperation, ValueError):
                return [], f'Orçamento #{idx}: histórico de preço inválido.'

            changed_at = None
            changed_at_raw = str(entry.get('changed_at') or '').strip()
            if changed_at_raw:
                candidate = changed_at_raw
                if candidate.endswith('Z'):
                    candidate = f'{candidate[:-1]}+00:00'
                try:
                    dt_value = datetime.fromisoformat(candidate)
                    if timezone.is_naive(dt_value):
                        dt_value = timezone.make_aware(dt_value, timezone.get_current_timezone())
                    changed_at = timezone.localtime(dt_value)
                except ValueError:
                    changed_at = None

            entry_id = None
            entry_id_raw = str(entry.get('id') or '').strip()
            if entry_id_raw.isdigit():
                entry_id = int(entry_id_raw)

            normalized_items.append(
                {
                    'id': entry_id,
                    'previous_value': previous_value,
                    'updated_value': updated_value,
                    'note': str(entry.get('note') or '').strip()[:300],
                    'changed_at': changed_at,
                }
            )
        return normalized_items, None

    @staticmethod
    def _sync_quote_price_history(quote: RequisitionQuote, history_items: list[dict]) -> None:
        existing_by_id = {item.id: item for item in quote.discount_entries.all()}
        keep_ids: set[int] = set()

        for item in history_items:
            previous_value = item.get('previous_value')
            updated_value = item.get('updated_value')
            delta_amount = (previous_value - updated_value) if previous_value is not None and updated_value is not None else Decimal('0')
            payload = {
                'amount': delta_amount,
                'previous_value': previous_value,
                'updated_value': updated_value,
                'changed_at': item.get('changed_at'),
                'note': item.get('note') or '',
            }

            entry_id = item.get('id')
            if entry_id and entry_id in existing_by_id:
                entry = existing_by_id[entry_id]
                entry.amount = payload['amount']
                entry.previous_value = payload['previous_value']
                entry.updated_value = payload['updated_value']
                entry.changed_at = payload['changed_at']
                entry.note = payload['note']
                entry.save(update_fields=['amount', 'previous_value', 'updated_value', 'changed_at', 'note'])
                keep_ids.add(entry.id)
                continue

            created = RequisitionQuoteDiscount.objects.create(quote=quote, **payload)
            keep_ids.add(created.id)

        quote.discount_entries.exclude(id__in=keep_ids).delete()

    def _save_quotes(self, request, requisition: Requisition, update_mode: bool = False) -> tuple[int, str | None]:
        existing_quotes = {}
        if update_mode:
            existing_quotes = {str(item.id): item for item in requisition.quotes.all()}
        kept_ids: set[int] = set()
        idx_to_quote: dict[str, RequisitionQuote] = {}
        saved_count = 0
        is_digital = requisition.kind == Requisition.Kind.DIGITAL

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
            payment_method_raw = (request.POST.get(f'budget_payment_method_{idx}') or '').strip()
            payment_installments_raw = (request.POST.get(f'budget_payment_installments_{idx}') or '').strip()
            price_history_raw = (request.POST.get(f'budget_price_history_json_{idx}') or '').strip()
            link = (request.POST.get(f'budget_link_{idx}') or '').strip()
            photo = request.FILES.get(f'budget_photo_{idx}')
            uploaded_files = request.FILES.getlist(f'budget_files_{idx}')
            photo_error = _validate_upload(photo, image_only=True)
            if photo_error:
                return 0, f'Orçamento #{idx}: {photo_error}'
            for file_obj in uploaded_files:
                file_error = _validate_upload(file_obj, image_only=False)
                if file_error:
                    return 0, f'Orçamento #{idx}: {file_error}'

            if not name and not value_raw and not link and not photo and not quote_id and not uploaded_files:
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

            payment_method = ''
            payment_installments = 1
            if is_digital:
                payment_method = payment_method_raw
                try:
                    payment_installments = int(payment_installments_raw or '1')
                except ValueError:
                    return 0, f'Orçamento #{idx}: parcelas inválidas.'
                if payment_installments <= 0:
                    return 0, f'Orçamento #{idx}: parcelas devem ser maiores que zero.'
            price_history_items: list[dict] = []
            if is_digital:
                price_history_items, history_error = self._parse_price_history_payload(price_history_raw, idx)
                if history_error:
                    return 0, history_error

            if update_mode and quote_id and quote_id in existing_quotes:
                quote = existing_quotes[quote_id]
                quote.name = name
                quote.quantity = quantity
                quote.value = value
                quote.freight = freight
                quote.payment_method = payment_method if is_digital else ''
                quote.payment_installments = payment_installments if is_digital else 1
                quote.link = link
                quote.parent = None
                quote.is_selected = False
                if photo:
                    quote.photo = photo
                    quote.save()
                else:
                    quote.save(
                        update_fields=[
                            'name',
                            'quantity',
                            'value',
                            'freight',
                            'payment_method',
                            'payment_installments',
                            'link',
                            'parent',
                            'is_selected',
                        ]
                    )
                if is_digital:
                    self._sync_quote_price_history(quote, price_history_items)
                    for file_obj in uploaded_files:
                        if file_obj:
                            RequisitionQuoteAttachment.objects.create(quote=quote, file=file_obj)
                else:
                    quote.discount_entries.all().delete()
                    quote.attachments.all().delete()
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
                payment_method=payment_method if is_digital else '',
                payment_installments=payment_installments if is_digital else 1,
                is_selected=False,
                link=link,
                photo=photo,
            )
            source_quote = None
            if source_quote_id:
                source_quote = RequisitionQuote.objects.filter(id=source_quote_id).first()
            if not photo and source_quote_id:
                if source_quote and source_quote.photo:
                    created.photo = source_quote.photo.name
                    created.save(update_fields=['photo'])
                if is_digital and source_quote:
                    for src_attachment in source_quote.attachments.all():
                        if src_attachment.file:
                            RequisitionQuoteAttachment.objects.create(quote=created, file=src_attachment.file.name)
                    if not created.payment_method and source_quote.payment_method:
                        created.payment_method = source_quote.payment_method
                        created.save(update_fields=['payment_method'])
                    if (
                        int(created.payment_installments or 1) <= 1
                        and int(source_quote.payment_installments or 1) > 1
                        and not payment_installments_raw
                    ):
                        created.payment_installments = int(source_quote.payment_installments or 1)
                        created.save(update_fields=['payment_installments'])
                    if not price_history_items:
                        for src_entry in source_quote.discount_entries.all():
                            if src_entry.previous_value is None or src_entry.updated_value is None:
                                continue
                            price_history_items.append(
                                {
                                    'id': None,
                                    'previous_value': src_entry.previous_value,
                                    'updated_value': src_entry.updated_value,
                                    'note': src_entry.note or '',
                                    'changed_at': src_entry.changed_at or src_entry.created_at,
                                }
                            )
            if is_digital:
                self._sync_quote_price_history(created, price_history_items)
                for file_obj in uploaded_files:
                    if file_obj:
                        RequisitionQuoteAttachment.objects.create(quote=created, file=file_obj)
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

        selected_quotes: list[RequisitionQuote] = []
        if is_digital:
            selected_idx_values = [str(v).strip() for v in request.POST.getlist('approved_budget_idx_list') if str(v).strip()]
            seen_idx: set[str] = set()
            for selected_idx in selected_idx_values:
                if selected_idx in seen_idx:
                    continue
                seen_idx.add(selected_idx)
                selected_quote = idx_to_quote.get(selected_idx)
                if not selected_quote:
                    continue
                if selected_quote.parent_id:
                    return 0, 'Selecione como aprovado apenas orçamento principal.'
                selected_quotes.append(selected_quote)
        else:
            selected_idx = (request.POST.get('approved_budget_idx') or '').strip()
            selected_quote = idx_to_quote.get(selected_idx) if selected_idx else None
            if selected_quote and selected_quote.parent_id:
                return 0, 'Selecione como aprovado apenas um orçamento principal.'
            if selected_quote:
                selected_quotes.append(selected_quote)

        requisition.quotes.update(is_selected=False)
        if selected_quotes:
            RequisitionQuote.objects.filter(id__in=[q.id for q in selected_quotes]).update(is_selected=True)

        if update_mode:
            requisition.quotes.exclude(id__in=kept_ids).delete()
        return saved_count, None

    @staticmethod
    def _parse_positive_int(raw_value: str, default: int = 0) -> int:
        try:
            value = int(str(raw_value or '').strip())
        except (TypeError, ValueError):
            return int(default)
        return value if value > 0 else int(default)

    @staticmethod
    def _fallback_requisition_quantity(requisition: Requisition) -> int:
        main_quote_max = (
            requisition.quotes.filter(parent__isnull=True).aggregate(max_qty=Max('quantity')).get('max_qty') or 0
        )
        base_qty = int(requisition.quantity or 0)
        return max(base_qty, int(main_quote_max or 0), 0)

    @staticmethod
    def _expected_delivery_quantity(requisition: Requisition) -> int:
        selected_total = (
            requisition.quotes.filter(parent__isnull=True, is_selected=True).aggregate(total=Sum('quantity')).get('total') or 0
        )
        selected_int = int(selected_total or 0)
        if selected_int > 0:
            return selected_int
        return RequisicoesView._fallback_requisition_quantity(requisition)

    @staticmethod
    def _sync_requisition_status_with_approved_quote(requisition: Requisition) -> None:
        has_selected_main = requisition.quotes.filter(parent__isnull=True, is_selected=True).exists()
        status_before = requisition.status
        if has_selected_main and requisition.status == Requisition.Status.PENDING_APPROVAL:
            requisition.status = Requisition.Status.APPROVED
        elif not has_selected_main and requisition.status in {Requisition.Status.APPROVED, Requisition.Status.PARTIALLY_RECEIVED}:
            requisition.status = Requisition.Status.PENDING_APPROVAL
        if requisition.status != status_before:
            requisition.save(update_fields=['status', 'updated_at'])

    @staticmethod
    def _sync_requisition_timeline_dates(requisition: Requisition) -> None:
        update_fields: list[str] = []
        if not requisition.requested_at:
            requisition.requested_at = requisition.created_at.date() if requisition.created_at else timezone.localdate()
            update_fields.append('requested_at')

        if requisition.status in {
            Requisition.Status.APPROVED,
            Requisition.Status.PARTIALLY_RECEIVED,
            Requisition.Status.RECEIVED,
        } and not requisition.approved_at:
            requisition.approved_at = timezone.localdate()
            update_fields.append('approved_at')

        if requisition.status == Requisition.Status.PARTIALLY_RECEIVED and not requisition.partially_received_at:
            requisition.partially_received_at = timezone.localdate()
            update_fields.append('partially_received_at')

        if requisition.status == Requisition.Status.RECEIVED and not requisition.received_at:
            requisition.received_at = timezone.localdate()
            update_fields.append('received_at')

        if update_fields:
            requisition.save(update_fields=update_fields)

    def post(self, request, *args, **kwargs):
        is_ti = is_ti_user(request)
        can_decide = can_decide_requisitions(request)
        if not can_decide:
            messages.error(request, 'Seu acesso em requisições é somente leitura.')
            return redirect('requisicoes')

        action = (request.POST.get('action') or '').strip().lower()
        if action == 'mark_approved_quote':
            requisition_id = (request.POST.get('requisition_id') or '').strip()
            quote_id = (request.POST.get('quote_id') or '').strip()
            requisition = Requisition.objects.filter(id=requisition_id).first()
            if not requisition:
                messages.error(request, 'Requisição não encontrada para aprovação.')
                return redirect('requisicoes')

            if requisition.status in {Requisition.Status.RECEIVED, Requisition.Status.PARTIALLY_RECEIVED}:
                messages.error(request, 'Requisições com entrega iniciada não podem ser aprovadas novamente.')
                return redirect('requisicoes')

            selected_quote = requisition.quotes.filter(id=quote_id, parent__isnull=True).first()
            if not selected_quote:
                messages.error(request, 'Orçamento principal inválido para aprovação.')
                return redirect('requisicoes')

            requisition.quotes.update(is_selected=False)
            selected_quote.is_selected = True
            selected_quote.save(update_fields=['is_selected'])

            requisition.status = Requisition.Status.APPROVED
            requisition.delivered_quantity = 0
            requisition.partially_received_at = None
            requisition.received_at = None
            requisition.save(update_fields=['status', 'delivered_quantity', 'partially_received_at', 'received_at', 'updated_at'])
            self._sync_requisition_timeline_dates(requisition)

            messages.success(request, f'Orçamento "{selected_quote.name}" aprovado para {requisition.code}.')
            return redirect('requisicoes')

        if action == 'mark_received':
            if not is_ti:
                messages.error(request, 'Somente TI pode marcar entrega.')
                return redirect('requisicoes')
            requisition_id = (request.POST.get('requisition_id') or '').strip()
            requisition = Requisition.objects.filter(id=requisition_id).first()
            if not requisition:
                messages.error(request, 'Requisição não encontrada para marcar entrega.')
                return redirect('requisicoes')

            self._sync_requisition_status_with_approved_quote(requisition)
            if requisition.status == Requisition.Status.RECEIVED:
                messages.success(request, 'Esta requisição já estava marcada como entregue.')
                return redirect('requisicoes')

            if requisition.status not in {Requisition.Status.APPROVED, Requisition.Status.PARTIALLY_RECEIVED}:
                messages.error(request, 'Apenas requisições aprovadas ou parcialmente entregues podem ser marcadas como entregues.')
                return redirect('requisicoes')

            expected_qty = self._expected_delivery_quantity(requisition)
            if expected_qty <= 0:
                expected_qty = int(requisition.quantity or 0)
            if expected_qty <= 0:
                messages.error(request, 'Não foi possível identificar a quantidade esperada da requisição.')
                return redirect('requisicoes')

            requisition.status = Requisition.Status.RECEIVED
            requisition.delivered_quantity = expected_qty
            requisition.save(update_fields=['status', 'delivered_quantity', 'updated_at'])
            self._sync_requisition_timeline_dates(requisition)
            messages.success(request, f'Requisição {requisition.code} marcada como entregue ({expected_qty}/{expected_qty}).')
            return redirect('requisicoes')
        if action == 'mark_partial_received':
            if not is_ti:
                messages.error(request, 'Somente TI pode registrar entrega parcial.')
                return redirect('requisicoes')
            requisition_id = (request.POST.get('requisition_id') or '').strip()
            requisition = Requisition.objects.filter(id=requisition_id).first()
            if not requisition:
                messages.error(request, 'Requisição não encontrada para entrega parcial.')
                return redirect('requisicoes')

            self._sync_requisition_status_with_approved_quote(requisition)
            if requisition.status == Requisition.Status.RECEIVED:
                messages.info(request, 'Esta requisição já está totalmente entregue.')
                return redirect('requisicoes')

            if requisition.status not in {Requisition.Status.APPROVED, Requisition.Status.PARTIALLY_RECEIVED}:
                messages.error(request, 'Apenas requisições aprovadas podem receber entrega parcial.')
                return redirect('requisicoes')

            add_qty = self._parse_positive_int(request.POST.get('delivered_quantity_add'), default=0)
            if add_qty <= 0:
                messages.error(request, 'Informe uma quantidade válida para entrega parcial.')
                return redirect('requisicoes')

            expected_qty = self._expected_delivery_quantity(requisition)
            if expected_qty <= 0:
                expected_qty = int(requisition.quantity or 0)
            if expected_qty <= 0:
                messages.error(request, 'Não foi possível identificar a quantidade esperada da requisição.')
                return redirect('requisicoes')

            delivered_current = int(requisition.delivered_quantity or 0)
            remaining = max(expected_qty - delivered_current, 0)
            if remaining <= 0:
                requisition.status = Requisition.Status.RECEIVED
                requisition.delivered_quantity = expected_qty
                requisition.save(update_fields=['status', 'delivered_quantity', 'updated_at'])
                self._sync_requisition_timeline_dates(requisition)
                messages.success(request, f'Requisição {requisition.code} já estava totalmente entregue ({expected_qty}/{expected_qty}).')
                return redirect('requisicoes')

            if add_qty > remaining:
                messages.error(request, f'Quantidade inválida. Restante para entrega: {remaining}.')
                return redirect('requisicoes')

            delivered_new = delivered_current + add_qty
            requisition.delivered_quantity = delivered_new
            if delivered_new >= expected_qty:
                requisition.status = Requisition.Status.RECEIVED
            else:
                requisition.status = Requisition.Status.PARTIALLY_RECEIVED
            requisition.save(update_fields=['status', 'delivered_quantity', 'updated_at'])
            self._sync_requisition_timeline_dates(requisition)

            if delivered_new >= expected_qty:
                messages.success(request, f'Entrega finalizada para {requisition.code} ({delivered_new}/{expected_qty}).')
            else:
                pending = expected_qty - delivered_new
                messages.success(
                    request,
                    f'Entrega parcial registrada para {requisition.code}: {delivered_new}/{expected_qty} entregue(s), pendente(s) {pending}.',
                )
            return redirect('requisicoes')
        if action == 'mark_rejected':
            requisition_id = (request.POST.get('requisition_id') or '').strip()
            requisition = Requisition.objects.filter(id=requisition_id).first()
            if not requisition:
                messages.error(request, 'Requisição não encontrada para marcar como não aprovada.')
                return redirect('requisicoes')

            if requisition.status == Requisition.Status.REJECTED:
                messages.success(request, 'Esta requisição já está marcada como não aprovada.')
                return redirect('requisicoes')

            if requisition.status in {Requisition.Status.RECEIVED, Requisition.Status.PARTIALLY_RECEIVED}:
                messages.error(request, 'Requisições com entrega iniciada não podem ser marcadas como não aprovadas.')
                return redirect('requisicoes')

            requisition.quotes.update(is_selected=False)
            requisition.status = Requisition.Status.REJECTED
            requisition.delivered_quantity = 0
            requisition.approved_at = None
            requisition.partially_received_at = None
            requisition.received_at = None
            requisition.save(
                update_fields=['status', 'delivered_quantity', 'approved_at', 'partially_received_at', 'received_at', 'updated_at']
            )
            messages.success(request, f'Requisição {requisition.code} marcada como não aprovada.')
            return redirect('requisicoes')

        if not is_ti:
            messages.error(request, 'Seu acesso em requisições é somente leitura.')
            return redirect('requisicoes')

        mode = (request.POST.get('mode') or 'create').strip().lower()
        kind_value = (request.POST.get('requisition_kind') or Requisition.Kind.PHYSICAL).strip()
        valid_kinds = {choice[0] for choice in Requisition.Kind.choices}
        if kind_value not in valid_kinds:
            kind_value = Requisition.Kind.PHYSICAL
        title_text = (request.POST.get('title') or '').strip()
        if not title_text:
            messages.error(request, 'Informe o título da requisição.')
            return redirect(request.get_full_path())

        request_text = (request.POST.get('request_text') or '').strip()
        if not request_text:
            messages.error(request, 'Informe o texto da requisição.')
            return redirect(request.get_full_path())

        if mode == 'update':
            requisition_id = (request.POST.get('requisition_id') or '').strip()
            requisition = Requisition.objects.filter(id=requisition_id).first()
            if not requisition:
                messages.error(request, 'Requisição não encontrada para edição.')
                return redirect(request.get_full_path())

            status_value = (request.POST.get('status') or Requisition.Status.PENDING_APPROVAL).strip()
            valid_statuses = {choice[0] for choice in Requisition.Status.choices}
            if status_value not in valid_statuses:
                status_value = Requisition.Status.PENDING_APPROVAL

            requisition.title = title_text
            requisition.kind = kind_value
            requisition.request = request_text
            requisition.status = status_value
            requisition.save(update_fields=['title', 'kind', 'request', 'status', 'updated_at'])

            saved_count, error = self._save_quotes(request, requisition, update_mode=True)
            if error:
                messages.error(request, error)
                return redirect(request.get_full_path())
            self._sync_requisition_status_with_approved_quote(requisition)
            self._sync_requisition_timeline_dates(requisition)

            messages.success(request, f'Requisição atualizada com sucesso com {saved_count} orçamento(s).')
            return redirect('requisicoes')

        requisition = Requisition.objects.create(
            title=title_text,
            kind=kind_value,
            request=request_text,
            requested_at=timezone.localdate(),
            status=Requisition.Status.PENDING_APPROVAL,
        )

        created_quotes, error = self._save_quotes(request, requisition, update_mode=False)
        if error:
            requisition.delete()
            messages.error(request, error)
            return redirect(request.get_full_path())
        self._sync_requisition_status_with_approved_quote(requisition)
        self._sync_requisition_timeline_dates(requisition)

        messages.success(request, f'Requisição cadastrada com sucesso com {created_quotes} orçamento(s).')
        return redirect('requisicoes')

    def get(self, request, *args, **kwargs):
        export_flag = (request.GET.get('export') or '').strip().lower()
        if export_flag in {'1', 'true', 'xlsx'}:
            is_ti = is_ti_user(request)
            can_readonly = can_view_requisitions_readonly(request)
            can_decide = can_decide_requisitions(request)
            can_view = is_ti or can_readonly or can_decide
            if not can_view:
                messages.error(request, 'Seu usuário não possui acesso para exportar requisições.')
                return redirect('chamados')
            context = self.get_context_data()
            requisitions = list(context.get('requisitions') or [])
            search_raw = (request.GET.get('q') or '').strip()
            status_raw = (request.GET.get('status') or '').strip()
            return self._export_excel(requisitions, search_raw=search_raw, status_raw=status_raw)
        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        is_ti = is_ti_user(self.request)
        can_readonly = can_view_requisitions_readonly(self.request)
        can_decide = can_decide_requisitions(self.request)
        can_view = is_ti or can_readonly or can_decide
        context['is_ti_group'] = is_ti
        context['can_manage_requisicoes'] = is_ti
        context['can_decide_requisicoes'] = can_decide
        context['can_view_requisicoes'] = can_view
        if is_ti:
            context['modules'] = build_modules('requisicoes')
        elif can_readonly or can_decide:
            context['modules'] = build_modules('requisicoes', allowed_slugs={'chamados', 'requisicoes'})
        else:
            context['modules'] = []

        if not can_view:
            context['requisitions'] = []
            return context

        requisitions = (
            Requisition.objects
            .prefetch_related('quotes__subquotes', 'quotes__attachments', 'quotes__discount_entries')
            .order_by('-created_at', '-id')
        )
        for req in requisitions:
            all_quotes = list(req.quotes.all())
            subs_by_parent: dict[int, list[RequisitionQuote]] = {}
            main_quotes: list[RequisitionQuote] = []
            selected_mains: list[RequisitionQuote] = []
            for quote in all_quotes:
                if quote.parent_id:
                    subs_by_parent.setdefault(quote.parent_id, []).append(quote)
                    continue
                main_quotes.append(quote)
                if quote.is_selected:
                    selected_mains.append(quote)

            selected_main = selected_mains[0] if selected_mains else None
            approved_quote_ids = {q.id for q in selected_mains}

            for quote in main_quotes:
                quote.sub_items = subs_by_parent.get(quote.id, [])
                quote.sub_items_count = len(quote.sub_items)
                quote.discount_items = list(
                    quote.discount_entries.exclude(previous_value__isnull=True).exclude(updated_value__isnull=True)
                )
                quote.price_history_count = len(quote.discount_items)
                quote.payment_installments = max(int(quote.payment_installments or 1), 1)
                quote.payment_method = (quote.payment_method or '').strip()
                package_total = (Decimal(quote.quantity or 1) * (quote.value or Decimal('0'))) + (quote.freight or Decimal('0'))
                for sub_item in quote.sub_items:
                    sub_item.discount_items = list(
                        sub_item.discount_entries.exclude(previous_value__isnull=True).exclude(updated_value__isnull=True)
                    )
                    sub_item.price_history_count = len(sub_item.discount_items)
                    sub_item.payment_installments = max(int(sub_item.payment_installments or 1), 1)
                    sub_item.payment_method = (sub_item.payment_method or '').strip()
                    package_total += (Decimal(sub_item.quantity or 1) * (sub_item.value or Decimal('0'))) + (sub_item.freight or Decimal('0'))
                quote.package_total = package_total
                quote.is_display_selected = quote.id in approved_quote_ids
                quote.attachment_items = list(quote.attachments.all())

            req.main_quotes = main_quotes
            req.main_quotes_count = len(main_quotes)
            req.sub_quotes_count = max(0, len(all_quotes) - len(main_quotes))
            req.approved_quote_id = selected_main.id if selected_main else None
            req.approved_quote_ids = approved_quote_ids
            req.kind_display = req.get_kind_display() if hasattr(req, 'get_kind_display') else ''
            req.rejected_at = req.updated_at.date() if req.status == Requisition.Status.REJECTED and req.updated_at else None
            selected_quantity = sum(int(q.quantity or 0) for q in selected_mains)
            fallback_qty = max(int(req.quantity or 0), max((int(q.quantity or 0) for q in main_quotes), default=0), 0)
            req.expected_delivery_quantity = selected_quantity if selected_quantity > 0 else fallback_qty
            if req.expected_delivery_quantity < 0:
                req.expected_delivery_quantity = 0
            delivered_quantity = int(req.delivered_quantity or 0)
            if req.status == Requisition.Status.RECEIVED and req.expected_delivery_quantity > 0 and delivered_quantity <= 0:
                delivered_quantity = req.expected_delivery_quantity
            if delivered_quantity < 0:
                delivered_quantity = 0
            if req.expected_delivery_quantity > 0:
                delivered_quantity = min(delivered_quantity, req.expected_delivery_quantity)
            req.delivered_quantity_display = delivered_quantity
            req.pending_delivery_quantity = max(req.expected_delivery_quantity - delivered_quantity, 0)

            if selected_mains:
                total = Decimal('0')
                for selected_item in selected_mains:
                    selected_total = (Decimal(selected_item.quantity or 1) * (selected_item.value or Decimal('0'))) + (selected_item.freight or Decimal('0'))
                    for sub_item in getattr(selected_item, 'sub_items', []):
                        selected_total += (Decimal(sub_item.quantity or 1) * (sub_item.value or Decimal('0'))) + (sub_item.freight or Decimal('0'))
                    total += selected_total
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
            return redirect(request.get_full_path())

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
        attachment_error = _validate_upload(attachment, image_only=False)
        if attachment_error:
            messages.error(request, attachment_error)
            return redirect(request.get_full_path())
        category = (request.POST.get('category') or Dica.Category.GERAL).strip()
        valid_categories = {choice[0] for choice in Dica.Category.choices}
        if category not in valid_categories:
            category = Dica.Category.GERAL

        if not title:
            messages.error(request, 'Informe o título da dica.')
            return redirect(request.get_full_path())
        if not content:
            messages.error(request, 'Informe a descrição da dica.')
            return redirect(request.get_full_path())

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


class AtribuicoesView(LoginRequiredMixin, TemplateView):
    template_name = 'core/atribuicoes.html'

    @classmethod
    def _load_atribuicoes_data(cls):
        ti_users = list(ERPUser.objects.filter(department__iexact='TI', is_active=True).order_by('full_name'))
        responsibilities = list(Responsibility.objects.prefetch_related('assignees').order_by('name', 'id'))
        responsibilities_by_user_id: dict[int, list[str]] = {user.id: [] for user in ti_users}

        for item in responsibilities:
            assignee_items = sorted(list(item.assignees.all()), key=lambda user: (user.full_name or '').lower())
            item.assignee_ids_csv = ','.join(str(user.id) for user in assignee_items)
            item.assignee_names = ', '.join(user.full_name for user in assignee_items) if assignee_items else ''
            for assignee in assignee_items:
                if assignee.id not in responsibilities_by_user_id:
                    responsibilities_by_user_id[assignee.id] = []
                responsibilities_by_user_id[assignee.id].append(item.name)

        ti_profiles_report = []
        for user in ti_users:
            responsibility_names = sorted(responsibilities_by_user_id.get(user.id, []), key=lambda value: value.lower())
            ti_profiles_report.append(
                {
                    'user': user,
                    'responsibility_names': responsibility_names,
                    'responsibility_names_text': ', '.join(responsibility_names),
                    'responsibility_count': len(responsibility_names),
                }
            )

        return ti_users, responsibilities, ti_profiles_report

    def post(self, request, *args, **kwargs):
        if not is_ti_user(request):
            messages.error(request, 'Apenas usuários do departamento TI podem gerenciar atribuições.')
            return redirect(request.get_full_path())

        action = (request.POST.get('action') or 'create_responsibility').strip().lower()

        if action in {'move_responsibility', 'update_responsibility'}:
            responsibility_id_raw = (request.POST.get('responsibility_id') or '').strip()
            target_user_ids_raw = request.POST.getlist('target_user_ids')

            try:
                responsibility_id = int(responsibility_id_raw)
            except (TypeError, ValueError):
                messages.error(request, 'Responsabilidade inválida para movimentação.')
                return redirect('atribuicoes')

            responsibility = Responsibility.objects.prefetch_related('assignees').filter(id=responsibility_id).first()
            if not responsibility:
                messages.error(request, 'Responsabilidade não encontrada.')
                return redirect('atribuicoes')

            target_user_ids: set[int] = set()
            for raw_id in target_user_ids_raw:
                value = (raw_id or '').strip()
                if not value:
                    continue
                try:
                    target_user_ids.add(int(value))
                except (TypeError, ValueError):
                    messages.error(request, 'Usuário TI inválido para movimentação.')
                    return redirect('atribuicoes')

            target_users = list(
                ERPUser.objects.filter(
                    id__in=target_user_ids,
                    department__iexact='TI',
                    is_active=True,
                ).order_by('full_name')
            )
            if len(target_users) != len(target_user_ids):
                messages.error(request, 'Um ou mais usuários TI não foram encontrados para receber a responsabilidade.')
                return redirect('atribuicoes')

            updated_name = (request.POST.get('name') or '').strip()
            if action == 'update_responsibility':
                if not updated_name:
                    messages.error(request, 'Informe o nome da responsabilidade.')
                    return redirect('atribuicoes')
                if Responsibility.objects.filter(name__iexact=updated_name).exclude(id=responsibility.id).exists():
                    messages.error(request, 'Já existe uma responsabilidade com esse nome.')
                    return redirect('atribuicoes')
            else:
                updated_name = responsibility.name

            current_users = list(responsibility.assignees.order_by('full_name'))
            current_ids = {item.id for item in current_users}
            current_name = (responsibility.name or '').strip()
            has_name_change = (updated_name or '').strip() != current_name
            has_assignee_change = current_ids != target_user_ids
            if not has_name_change and not has_assignee_change:
                messages.info(request, 'Nenhuma alteração foi identificada para esta responsabilidade.')
                return redirect('atribuicoes')

            if has_name_change:
                responsibility.name = updated_name
                responsibility.save(update_fields=['name', 'updated_at'])
            if has_assignee_change:
                responsibility.assignees.set(target_users)

            old_assignee_names = ', '.join(item.full_name for item in current_users) if current_users else 'Sem responsável'
            new_assignee_names = ', '.join(item.full_name for item in target_users) if target_users else 'Sem responsável'
            if has_name_change and has_assignee_change:
                messages.success(
                    request,
                    f'Responsabilidade atualizada: nome "{current_name}" -> "{updated_name}" e atendentes {old_assignee_names} -> {new_assignee_names}.',
                )
            elif has_name_change:
                messages.success(request, f'Nome da responsabilidade alterado: "{current_name}" -> "{updated_name}".')
            else:
                messages.success(
                    request,
                    f'Responsabilidade "{responsibility.name}" atualizada: {old_assignee_names} -> {new_assignee_names}.',
                )
            return redirect('atribuicoes')

        if action == 'create_responsibility':
            name = (request.POST.get('name') or '').strip()

            if not name:
                messages.error(request, 'Informe o nome da responsabilidade.')
                return redirect('atribuicoes')

            if Responsibility.objects.filter(name__iexact=name).exists():
                messages.error(request, 'Já existe uma responsabilidade com esse nome.')
                return redirect('atribuicoes')

            Responsibility.objects.create(name=name)
            messages.success(request, 'Responsabilidade cadastrada com sucesso.')
            return redirect('atribuicoes')

        messages.error(request, 'Ação inválida para atribuições.')
        return redirect('atribuicoes')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        is_ti = is_ti_user(self.request)
        context['is_ti_group'] = is_ti
        context['modules'] = build_modules('atribuicoes') if is_ti else []
        context['ti_users'] = []
        context['responsibilities'] = []
        context['ti_profiles_report'] = []
        if not is_ti:
            return context

        ti_users, responsibilities, ti_profiles_report = self._load_atribuicoes_data()
        context['ti_users'] = ti_users
        context['responsibilities'] = responsibilities
        context['ti_profiles_report'] = ti_profiles_report
        return context


class AtribuicoesReportView(LoginRequiredMixin, TemplateView):
    template_name = 'core/atribuicoes_report.html'

    def dispatch(self, request, *args, **kwargs):
        if not is_ti_user(request):
            messages.error(request, 'Apenas usuários do departamento TI podem visualizar o relatório de atribuições.')
            return redirect('atribuicoes')
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        _, responsibilities, ti_profiles_report = AtribuicoesView._load_atribuicoes_data()
        context['responsibilities'] = responsibilities
        context['ti_profiles_report'] = ti_profiles_report
        context['generated_at'] = timezone.localtime(timezone.now())
        return context


class PendenciasView(LoginRequiredMixin, TemplateView):
    template_name = 'core/pendencias.html'

    def post(self, request, *args, **kwargs):
        if not is_ti_user(request):
            messages.error(request, 'Apenas usuarios do departamento TI podem gerenciar pendencias.')
            return redirect(request.get_full_path())

        action = (request.POST.get('action') or 'create_pendency').strip().lower()

        if action == 'set_done_status':
            pendency_id_raw = (request.POST.get('pendency_id') or '').strip()
            try:
                pendency_id = int(pendency_id_raw)
            except (TypeError, ValueError):
                messages.error(request, 'Pendencia invalida para atualizacao.')
                return redirect('pendencias')

            pendency = Pendencia.objects.select_related('attendant').filter(id=pendency_id).first()
            if not pendency:
                messages.error(request, 'Pendencia nao encontrada.')
                return redirect('pendencias')

            new_done = bool(request.POST.get('is_done'))
            if new_done == bool(pendency.is_done):
                messages.info(request, 'Nenhuma alteracao foi identificada para essa pendencia.')
                return redirect('pendencias')

            pendency.is_done = new_done
            pendency.done_at = timezone.now() if new_done else None
            pendency.save(update_fields=['is_done', 'done_at', 'updated_at'])
            if new_done:
                messages.success(request, 'Pendencia marcada como concluida.')
            else:
                messages.success(request, 'Pendencia retornou para pendente.')
            return redirect('pendencias')

        if action == 'create_pendency':
            attendant_id_raw = (request.POST.get('attendant_id') or '').strip()
            description = (request.POST.get('description') or '').strip()

            if not description:
                messages.error(request, 'Informe a pendencia.')
                return redirect('pendencias')

            try:
                attendant_id = int(attendant_id_raw)
            except (TypeError, ValueError):
                messages.error(request, 'Atendente TI invalido.')
                return redirect('pendencias')

            attendant = ERPUser.objects.filter(
                id=attendant_id,
                department__iexact='TI',
                is_active=True,
            ).first()
            if not attendant:
                messages.error(request, 'Atendente TI nao encontrado.')
                return redirect('pendencias')

            Pendencia.objects.create(
                attendant=attendant,
                description=description,
                is_done=False,
            )
            messages.success(request, 'Pendencia cadastrada com sucesso.')
            return redirect('pendencias')

        messages.error(request, 'Acao invalida para pendencias.')
        return redirect('pendencias')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        is_ti = is_ti_user(self.request)
        context['is_ti_group'] = is_ti
        context['modules'] = build_modules('pendencias') if is_ti else []
        context['ti_users'] = []
        context['default_pendency_attendant_id'] = None
        context['pending_items'] = []
        context['completed_items'] = []
        if not is_ti:
            return context

        ti_users = ERPUser.objects.filter(department__iexact='TI', is_active=True).order_by('full_name')
        context['ti_users'] = ti_users
        default_attendant = ti_users.filter(full_name__iexact='Fabiano Polone').first() or ti_users.first()
        context['default_pendency_attendant_id'] = default_attendant.id if default_attendant else None
        context['pending_items'] = (
            Pendencia.objects.select_related('attendant')
            .filter(is_done=False)
            .order_by('-created_at', '-id')
        )
        context['completed_items'] = (
            Pendencia.objects.select_related('attendant')
            .filter(is_done=True)
            .order_by('-done_at', '-updated_at', '-id')
        )
        return context


@login_required
@require_POST
def pendencias_toggle_status_api(request):
    if not is_ti_user(request):
        return JsonResponse({'ok': False, 'error': 'forbidden'}, status=403)

    pendency_id_raw = (request.POST.get('pendency_id') or '').strip()
    try:
        pendency_id = int(pendency_id_raw)
    except (TypeError, ValueError):
        return JsonResponse({'ok': False, 'error': 'invalid_pendency_id'}, status=400)

    pendency = Pendencia.objects.select_related('attendant').filter(id=pendency_id).first()
    if not pendency:
        return JsonResponse({'ok': False, 'error': 'pendency_not_found'}, status=404)

    new_done = bool(request.POST.get('is_done'))
    changed = bool(pendency.is_done) != new_done
    if changed:
        pendency.is_done = new_done
        pendency.done_at = timezone.now() if new_done else None
        pendency.save(update_fields=['is_done', 'done_at', 'updated_at'])

    when_dt = pendency.done_at if pendency.is_done else pendency.created_at
    when_text = timezone.localtime(when_dt).strftime('%d/%m/%Y %H:%M') if when_dt else ''
    return JsonResponse(
        {
            'ok': True,
            'changed': changed,
            'item': {
                'id': pendency.id,
                'attendant_id': pendency.attendant_id,
                'description': pendency.description,
                'is_done': bool(pendency.is_done),
                'when_text': when_text,
            },
        }
    )


@login_required
@require_POST
def pendencias_create_api(request):
    if not is_ti_user(request):
        return JsonResponse({'ok': False, 'error': 'forbidden'}, status=403)

    attendant_id_raw = (request.POST.get('attendant_id') or '').strip()
    description = (request.POST.get('description') or '').strip()
    if not description:
        return JsonResponse({'ok': False, 'error': 'description_required'}, status=400)

    try:
        attendant_id = int(attendant_id_raw)
    except (TypeError, ValueError):
        return JsonResponse({'ok': False, 'error': 'invalid_attendant_id'}, status=400)

    attendant = ERPUser.objects.filter(
        id=attendant_id,
        department__iexact='TI',
        is_active=True,
    ).first()
    if not attendant:
        return JsonResponse({'ok': False, 'error': 'attendant_not_found'}, status=404)

    pendency = Pendencia.objects.create(
        attendant=attendant,
        description=description,
        is_done=False,
    )
    when_text = timezone.localtime(pendency.created_at).strftime('%d/%m/%Y %H:%M') if pendency.created_at else ''
    return JsonResponse(
        {
            'ok': True,
            'item': {
                'id': pendency.id,
                'attendant_id': pendency.attendant_id,
                'description': pendency.description,
                'is_done': False,
                'when_text': when_text,
            },
        }
    )


@login_required
@require_POST
def pendencias_create_ticket_api(request):
    if not is_ti_user(request):
        return JsonResponse({'ok': False, 'error': 'forbidden'}, status=403)

    pendency_id_raw = (request.POST.get('pendency_id') or '').strip()
    try:
        pendency_id = int(pendency_id_raw)
    except (TypeError, ValueError):
        return JsonResponse({'ok': False, 'error': 'invalid_pendency_id'}, status=400)

    pendency = Pendencia.objects.select_related('attendant').filter(id=pendency_id).first()
    if not pendency:
        return JsonResponse({'ok': False, 'error': 'pendency_not_found'}, status=404)
    if pendency.is_done:
        return JsonResponse({'ok': False, 'error': 'pendency_already_done'}, status=400)

    attendant = pendency.attendant
    if not attendant or not attendant.is_active or (attendant.department or '').strip().upper() != 'TI':
        return JsonResponse({'ok': False, 'error': 'attendant_not_available'}, status=400)

    description = (pendency.description or '').strip()
    if not description:
        return JsonResponse({'ok': False, 'error': 'empty_pendency_description'}, status=400)

    title = description[:200]
    now_dt = timezone.now()

    ticket = Ticket.objects.create(
        title=title,
        description=description,
        ticket_type=Ticket.TicketType.PROGRAMADO,
        urgency=Ticket.Urgency.PROGRAMADA,
        status=Ticket.Status.EM_ATENDIMENTO,
        created_by=request.user,
        assigned_to=attendant,
    )

    cycle = _get_ticket_attendant_cycle(ticket, attendant.id, create=True)
    if cycle and not cycle.current_cycle_started_at:
        cycle.current_cycle_started_at = now_dt
        cycle.save(update_fields=['current_cycle_started_at', 'updated_at'])
    _sync_ticket_cycle_snapshot(ticket)

    _log_ticket_timeline(
        ticket=ticket,
        event_type=TicketTimelineEvent.EventType.CREATED,
        request_user=request.user,
        to_status=Ticket.Status.EM_ATENDIMENTO,
        note=f'Chamado criado a partir da pendencia #{pendency.id}.',
    )
    _log_ticket_timeline(
        ticket=ticket,
        event_type=TicketTimelineEvent.EventType.ASSIGNED,
        request_user=request.user,
        from_status=Ticket.Status.EM_ATENDIMENTO,
        to_status=Ticket.Status.EM_ATENDIMENTO,
        note=f'Play iniciado para {attendant.full_name}.',
    )

    pendency.is_done = True
    pendency.done_at = now_dt
    pendency.save(update_fields=['is_done', 'done_at', 'updated_at'])
    when_text = timezone.localtime(pendency.done_at).strftime('%d/%m/%Y %H:%M') if pendency.done_at else ''

    return JsonResponse(
        {
            'ok': True,
            'ticket': {
                'id': ticket.id,
                'title': ticket.title,
            },
            'pendency': {
                'id': pendency.id,
                'attendant_id': pendency.attendant_id,
                'description': pendency.description,
                'is_done': True,
                'when_text': when_text,
            },
        }
    )


class AcessosView(LoginRequiredMixin, TemplateView):
    template_name = 'core/acessos.html'

    def post(self, request, *args, **kwargs):
        if not is_ti_user(request):
            messages.error(request, 'Apenas usuários do departamento TI podem atualizar acessos.')
            return redirect(request.get_full_path())

        root_path = getattr(settings, 'ACCESS_ROOT_PATH', '')
        try:
            folders, groups, members = refresh_access_snapshot(root_path)
            messages.success(request, f'Atualização concluída: {folders} pastas, {groups} grupos, {members} membros.')
        except Exception as exc:
            messages.error(request, f'Falha ao atualizar acessos: {exc}')
        return redirect(request.get_full_path())

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
        attachment_error = _validate_upload(attachment, image_only=False)
        if attachment_error:
            messages.error(request, attachment_error)
            return redirect(request.get_full_path())
        creator_user = request.user
        opened_at_dt = None

        if not title or not description:
            messages.error(request, 'Preencha título e descrição.')
            return redirect(request.get_full_path())

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
            return redirect(request.get_full_path())
        else:
            requester_user_id = (request.POST.get('requester_user_id') or '').strip()
            opened_at_raw = (request.POST.get('opened_at') or '').strip()
            if requester_user_id:
                try:
                    requester_id = int(requester_user_id)
                except ValueError:
                    messages.error(request, 'Solicitante inválido.')
                    return redirect(request.get_full_path())
                requester_erp_user = ERPUser.objects.filter(id=requester_id, is_active=True).first()
                if not requester_erp_user:
                    messages.error(request, 'Solicitante não encontrado.')
                    return redirect(request.get_full_path())
                requester_auth_user = _get_or_create_auth_user_for_erp(requester_erp_user)
                if not requester_auth_user:
                    messages.error(request, 'Solicitante sem login válido para abertura.')
                    return redirect(request.get_full_path())
                creator_user = requester_auth_user
            if opened_at_raw:
                try:
                    opened_at_dt = datetime.fromisoformat(opened_at_raw)
                    if timezone.is_naive(opened_at_dt):
                        opened_at_dt = timezone.make_aware(opened_at_dt, timezone.get_current_timezone())
                except ValueError:
                    messages.error(request, 'Data/hora de abertura inválida.')
                    return redirect(request.get_full_path())

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
        # Protege contra cliques múltiplos quase simultâneos: mantém apenas o primeiro chamado.
        first_recent_id = (
            Ticket.objects.filter(
                created_by=creator_user,
                title=title,
                description=description,
                created_at__gte=recent_cutoff,
            )
            .order_by('id')
            .values_list('id', flat=True)
            .first()
        )
        if first_recent_id and first_recent_id != ticket.id:
            ticket.delete()
            messages.info(request, 'Chamado idêntico detectado em envio repetido. Mantivemos apenas o primeiro.')
            return redirect('chamados')

        if opened_at_dt:
            Ticket.objects.filter(id=ticket.id).update(created_at=opened_at_dt)
            ticket.created_at = opened_at_dt
        _log_ticket_timeline(
            ticket=ticket,
            event_type=TicketTimelineEvent.EventType.CREATED,
            request_user=request.user,
            to_status=initial_status,
            note=f'Chamado criado no quadro como {_timeline_status_label(initial_status)}.',
            event_created_at=ticket.created_at,
        )
        _enqueue_new_ticket_notifications(ticket.id)
        messages.success(request, 'Chamado aberto com sucesso.')
        return redirect('chamados')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        is_ti = is_ti_user(self.request)
        can_readonly_requisitions = can_view_requisitions_readonly(self.request) or can_decide_requisitions(self.request)
        context['is_ti_group'] = is_ti
        if is_ti:
            context['modules'] = build_modules('chamados')
        elif can_readonly_requisitions:
            context['modules'] = build_modules('chamados', allowed_slugs={'chamados', 'requisicoes'})
        else:
            context['modules'] = []
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
        ti_usernames_set = {(item.username or '').strip().lower() for item in ti_users if (item.username or '').strip()}
        attendant_pendencias_map: dict[int, dict[str, list[dict[str, str | int]]]] = {
            user.id: {'pending': [], 'completed': []}
            for user in ti_users
        }
        last_paths: dict[int, str] = {}
        ti_ids = [u.id for u in ti_users]
        if ti_ids:
            pend_rows = (
                Pendencia.objects.filter(attendant_id__in=ti_ids)
                .order_by('-created_at', '-id')
                .values('id', 'attendant_id', 'description', 'is_done', 'created_at', 'done_at')
            )
            for row in pend_rows:
                attendant_id = int(row.get('attendant_id') or 0)
                bucket = attendant_pendencias_map.get(attendant_id)
                if not bucket:
                    continue
                description = (row.get('description') or '').strip() or '-'
                payload = {
                    'id': int(row.get('id') or 0),
                    'description': description,
                    'when_text': '',
                }
                if row.get('is_done'):
                    done_at = row.get('done_at') or row.get('created_at')
                    if done_at:
                        payload['when_text'] = timezone.localtime(done_at).strftime('%d/%m/%Y %H:%M')
                    bucket['completed'].append(payload)
                else:
                    created_at = row.get('created_at')
                    if created_at:
                        payload['when_text'] = timezone.localtime(created_at).strftime('%d/%m/%Y %H:%M')
                    bucket['pending'].append(payload)
        context['attendant_pendencias_map'] = attendant_pendencias_map
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
        ti_requester_subquery = ERPUser.objects.filter(
            department__iexact='TI',
            username__iexact=OuterRef('created_by__username'),
        )
        context['new_tickets'] = (
            Ticket.objects.filter(
                status__in=[Ticket.Status.NOVO, Ticket.Status.PENDENTE, Ticket.Status.PROGRAMADO],
                assigned_to__isnull=True,
                collaborators__isnull=True,
            )
            .select_related('created_by')
            .annotate(
                requester_is_ti=Exists(ti_requester_subquery),
                requester_priority=Case(
                    When(requester_is_ti=True, then=Value(1)),
                    default=Value(0),
                    output_field=IntegerField(),
                ),
                urgency_priority=Case(
                    When(urgency=Ticket.Urgency.ALTA, then=Value(0)),
                    When(urgency=Ticket.Urgency.MEDIA, then=Value(1)),
                    When(urgency=Ticket.Urgency.BAIXA, then=Value(2)),
                    When(urgency=Ticket.Urgency.PROGRAMADA, then=Value(3)),
                    When(urgency=Ticket.Urgency.NAO_CLASSIFICADO, then=Value(4)),
                    default=Value(5),
                    output_field=IntegerField(),
                ),
                queue_order=Case(
                    When(status=Ticket.Status.NOVO, then=Value(0)),
                    When(status=Ticket.Status.PENDENTE, then=Value(1)),
                    default=Value(2),
                    output_field=IntegerField(),
                )
            )
            .distinct()
            .order_by('requester_priority', 'urgency_priority', 'queue_order', '-created_at')
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
            username_norm = (username or '').strip().lower()
            is_requester_ti = bool(erp and (erp.department or '').strip().upper() == 'TI') or username_norm in ti_usernames_set
            name = erp.full_name if erp and erp.full_name else username
            dept = erp.department if erp else ''
            urgency_priority = {
                Ticket.Urgency.ALTA: 0,
                Ticket.Urgency.MEDIA: 1,
                Ticket.Urgency.BAIXA: 2,
                Ticket.Urgency.PROGRAMADA: 3,
                Ticket.Urgency.NAO_CLASSIFICADO: 4,
            }.get(ticket.urgency, 5)
            ticket_meta[ticket.id] = {
                'requester': name or '- ',
                'department': dept or '',
                'description': ticket.description or '',
                'requester_priority': 1 if is_requester_ti else 0,
                'urgency_priority': urgency_priority,
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


def _can_delete_ticket(request, ticket: Ticket) -> bool:
    if not ticket:
        return False
    if ticket.status == Ticket.Status.CANCELADO:
        return False
    if getattr(request.user, 'id', None) and ticket.created_by_id == request.user.id:
        return True
    if not is_ti_user(request):
        return False
    return TicketTimelineEvent.objects.filter(
        ticket=ticket,
        event_type=TicketTimelineEvent.EventType.CREATED,
        actor_user_id=getattr(request.user, 'id', None),
    ).exists()


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
    can_delete = _can_delete_ticket(request, ticket)
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
            'can_delete': can_delete,
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
    attachment_error = _validate_upload(attachment, image_only=False)
    if attachment_error:
        return JsonResponse({'ok': False, 'error': 'invalid_attachment', 'detail': attachment_error}, status=400)

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
def ticket_delete(request):
    ticket_id = request.POST.get('ticket_id')
    if not ticket_id:
        return JsonResponse({'ok': False, 'error': 'invalid'}, status=400)

    ticket = Ticket.objects.filter(id=ticket_id).first()
    if not ticket:
        return JsonResponse({'ok': False, 'error': 'not_found'}, status=404)

    if not _can_delete_ticket(request, ticket):
        return JsonResponse({'ok': False, 'error': 'forbidden'}, status=403)

    previous_status = ticket.status
    TicketAttendantCycle.objects.filter(ticket=ticket).exclude(current_cycle_started_at__isnull=True).update(
        current_cycle_started_at=None,
        updated_at=timezone.now(),
    )
    ticket.current_cycle_started_at = None
    ticket.status = Ticket.Status.CANCELADO
    ticket.save(update_fields=['status', 'current_cycle_started_at', 'updated_at'])
    _sync_ticket_cycle_snapshot(ticket)
    _log_ticket_timeline(
        ticket=ticket,
        event_type=TicketTimelineEvent.EventType.STATUS_CHANGED,
        request_user=request.user,
        from_status=previous_status,
        to_status=Ticket.Status.CANCELADO,
        note='Chamado cancelado (registro mantido para auditoria).',
    )
    return JsonResponse({'ok': True, 'cancelled': True})


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


@require_GET
def app_version_api(request):
    version, source = _resolve_app_version()
    return JsonResponse({'ok': True, 'version': version, 'source': source})


@login_required
@require_GET
def chamados_new_alert_api(request):
    if not is_ti_user(request):
        return JsonResponse({'ok': False, 'error': 'forbidden'}, status=403)

    since_raw = (request.GET.get('since_id') or '').strip()
    try:
        since_id = int(since_raw) if since_raw else 0
    except ValueError:
        since_id = 0
    if since_id < 0:
        since_id = 0

    latest_id = Ticket.objects.order_by('-id').values_list('id', flat=True).first() or 0
    new_qs = (
        Ticket.objects.filter(id__gt=since_id)
        .select_related('created_by')
        .order_by('id')[:25]
    )
    items = [
        {
            'id': item.id,
            'title': (item.title or '').strip(),
            'status': item.status,
            'created_at': timezone.localtime(item.created_at).strftime('%d/%m/%Y %H:%M') if item.created_at else '',
            'requester': (item.created_by.get_full_name() or item.created_by.username) if item.created_by else '',
        }
        for item in new_qs
    ]

    return JsonResponse(
        {
            'ok': True,
            'latest_id': int(latest_id),
            'count': len(items),
            'tickets': items,
        }
    )


def _resolve_media_file(relative_path: str) -> tuple[str, Path]:
    normalized = (relative_path or '').strip().replace('\\', '/').lstrip('/')
    if not normalized:
        raise Http404('Arquivo nao encontrado.')
    media_root = Path(getattr(settings, 'MEDIA_ROOT', '') or '').resolve()
    candidate = (media_root / normalized).resolve()
    if not media_root.exists():
        raise Http404('Media indisponivel.')
    if media_root != candidate and media_root not in candidate.parents:
        raise Http404('Arquivo invalido.')
    if not candidate.is_file():
        raise Http404('Arquivo nao encontrado.')
    return normalized, candidate


def _can_access_media_file(request, relative_path: str) -> bool:
    path_lower = (relative_path or '').lower()
    ti_user = is_ti_user(request)
    can_ro_requisitions = can_view_requisitions_readonly(request) or can_decide_requisitions(request)

    if path_lower.startswith('tickets/'):
        ticket = Ticket.objects.filter(attachment=relative_path).first()
        if not ticket:
            return ti_user
        return ti_user or ticket.created_by_id == request.user.id

    if path_lower.startswith('ticket_messages/'):
        message = TicketMessage.objects.select_related('ticket').filter(attachment=relative_path).first()
        if not message:
            return ti_user
        return ti_user or message.created_by_id == request.user.id or message.ticket.created_by_id == request.user.id

    if path_lower.startswith('requisitions/'):
        return ti_user or can_ro_requisitions

    if path_lower.startswith('dicas/'):
        return ti_user

    return ti_user


@login_required
@require_GET
def protected_media(request, path: str):
    relative_path, file_path = _resolve_media_file(path)
    if not _can_access_media_file(request, relative_path):
        return JsonResponse({'ok': False, 'error': 'forbidden'}, status=403)

    content_type, _ = mimetypes.guess_type(file_path.name)
    response = FileResponse(open(file_path, 'rb'), content_type=content_type or 'application/octet-stream')
    response['X-Content-Type-Options'] = 'nosniff'
    return response


@csrf_exempt
@require_POST
def inventory_push_api(request):
    if not _inventory_agent_token():
        return JsonResponse({'ok': False, 'error': 'inventory_agent_token_not_configured'}, status=503)

    if not _is_valid_inventory_agent_request(request):
        return JsonResponse({'ok': False, 'error': 'unauthorized'}, status=401)

    raw_body = request.body or b''
    max_payload_bytes = int(getattr(settings, 'INVENTORY_AGENT_MAX_PAYLOAD_BYTES', 2 * 1024 * 1024) or (2 * 1024 * 1024))
    if len(raw_body) > max_payload_bytes:
        return JsonResponse({'ok': False, 'error': 'payload_too_large'}, status=413)

    try:
        body_text = raw_body.decode('utf-8')
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
            error_message = f'{host}: erro ({exc})'
            messages_list.append(error_message)
            logger.exception('Falha ao processar payload de inventário do agente: host=%s', host)

    status = 200 if ok_count else 400
    try:
        log_audit_event(
            event_type=AuditLog.EventType.SYSTEM,
            description='Recebeu inventario via agente GPO',
            details=f'processed={len(items)} updated={ok_count} failed={failed_count}',
            status_code=status,
            route_name='inventory_push_api',
            path='/api/inventory/push/',
            method='POST',
        )
    except Exception:
        pass

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


class AuditoriaView(LoginRequiredMixin, TemplateView):
    template_name = 'core/auditoria.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        is_ti = is_ti_user(self.request)
        context['is_ti_group'] = is_ti
        context['modules'] = build_modules('auditoria') if is_ti else []

        logs = AuditLog.objects.all()
        q = (self.request.GET.get('q') or '').strip()
        event_type = (self.request.GET.get('tipo') or '').strip()
        if q:
            logs = logs.filter(
                Q(description__icontains=q)
                | Q(details__icontains=q)
                | Q(username__icontains=q)
                | Q(full_name__icontains=q)
                | Q(path__icontains=q)
                | Q(route_name__icontains=q)
            )
        if event_type in {AuditLog.EventType.ACCESS, AuditLog.EventType.ACTION, AuditLog.EventType.SYSTEM}:
            logs = logs.filter(event_type=event_type)

        context['audit_logs'] = logs.order_by('-created_at', '-id')[:500]
        context['audit_total_count'] = logs.count()
        context['audit_q'] = q
        context['audit_tipo'] = event_type
        context['audit_event_types'] = AuditLog.EventType.choices
        return context


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
