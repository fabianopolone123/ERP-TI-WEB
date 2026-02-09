import logging
import unicodedata
from textwrap import shorten
from decimal import Decimal, InvalidOperation
from django.conf import settings
from django.contrib import messages
from django.core.mail import send_mail
from django.shortcuts import redirect
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import JsonResponse
from django.urls import reverse
from django.views.decorators.http import require_GET, require_POST
from django.views.generic import TemplateView
from django.contrib.auth import views as auth_views
from ldap3 import Connection, Server, SUBTREE
from ldap3.utils.conv import escape_filter_chars

from .ldap_importer import import_ad_users
from .models import (
    ERPUser,
    Equipment,
    Requisition,
    AccessFolder,
    AccessMember,
    Ticket,
    TicketMessage,
    WhatsAppTemplate,
    EmailTemplate,
    WhatsAppNotificationSettings,
    WhatsAppOptOut,
)
from .wapi import find_whatsapp_groups_by_name, send_whatsapp_message
from .access_importer import refresh_access_snapshot

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
    'new_ticket': 'Novo chamado #{id}: {title} | {description}',
    'status_update': 'Chamado #{id} atualizado: {status} | {responsavel}',
    'new_message': 'Nova mensagem no chamado #{id}: {message}',
}

ERP_MODULES = [
    {'slug': 'usuarios', 'label': 'Usuários', 'url_name': 'usuarios'},
    {'slug': 'acessos', 'label': 'Acessos', 'url_name': 'acessos'},
    {'slug': 'equipamentos', 'label': 'Equipamentos', 'url_name': 'equipamentos'},
    {'slug': 'ips', 'label': 'IPs', 'url_name': None},
    {'slug': 'emails', 'label': 'Emails', 'url_name': None},
    {'slug': 'ramais', 'label': 'Ramais', 'url_name': None},
    {'slug': 'softwares', 'label': 'Softwares', 'url_name': None},
    {'slug': 'insumos', 'label': 'Insumos', 'url_name': None},
    {'slug': 'requisicoes', 'label': 'Requisições', 'url_name': 'requisicoes'},
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

    templates = _get_whatsapp_templates()
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
    recipient = getattr(ticket.created_by, 'email', '')
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

        Equipment.objects.create(
            sector=request.POST.get('sector', '').strip(),
            user=request.POST.get('user', '').strip(),
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
        return context


class RequisicoesView(LoginRequiredMixin, TemplateView):
    template_name = 'core/requisicoes.html'

    def post(self, request, *args, **kwargs):
        if not is_ti_user(request):
            messages.error(request, 'Apenas usuários do departamento TI podem cadastrar requisições.')
            return self.get(request, *args, **kwargs)

        request_text = (request.POST.get('request') or '').strip()
        if not request_text:
            messages.error(request, 'Informe a solicitação.')
            return self.get(request, *args, **kwargs)

        quantity_raw = (request.POST.get('quantity') or '').strip()
        unit_value_raw = (request.POST.get('unit_value') or '').strip()
        try:
            quantity = int(quantity_raw or '1')
            if quantity < 1:
                raise ValueError
        except ValueError:
            messages.error(request, 'Quantidade inválida.')
            return self.get(request, *args, **kwargs)

        try:
            normalized_value = unit_value_raw.replace(' ', '')
            if ',' in normalized_value and '.' in normalized_value:
                if normalized_value.rfind(',') > normalized_value.rfind('.'):
                    normalized_value = normalized_value.replace('.', '').replace(',', '.')
                else:
                    normalized_value = normalized_value.replace(',', '')
            elif ',' in normalized_value:
                normalized_value = normalized_value.replace('.', '').replace(',', '.')
            elif normalized_value.count('.') > 1:
                normalized_value = normalized_value.replace('.', '')

            unit_value = Decimal(normalized_value or '0')
            if unit_value < 0:
                raise InvalidOperation
        except (InvalidOperation, ValueError):
            messages.error(request, 'Valor unitário inválido.')
            return self.get(request, *args, **kwargs)

        Requisition.objects.create(
            request=request_text,
            quantity=quantity,
            unit_value=unit_value,
            requested_at=(request.POST.get('requested_at') or '').strip() or None,
            approved_at=(request.POST.get('approved_at') or '').strip() or None,
            received_at=(request.POST.get('received_at') or '').strip() or None,
            invoice=(request.POST.get('invoice') or '').strip(),
            req_type=(request.POST.get('req_type') or '').strip(),
            link=(request.POST.get('link') or '').strip(),
        )
        messages.success(request, 'Requisição cadastrada com sucesso.')
        return redirect('requisicoes')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        is_ti = is_ti_user(self.request)
        context['is_ti_group'] = is_ti
        context['modules'] = build_modules('requisicoes') if is_ti else []
        requisitions = Requisition.objects.all().order_by('-requested_at', '-id')
        context['requisitions'] = requisitions
        context['types'] = sorted({(item.req_type or '').strip() for item in requisitions if (item.req_type or '').strip()})
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

        ticket = Ticket.objects.create(
            title=title,
            description=description,
            ticket_type=ticket_type,
            urgency=urgency,
            status=Ticket.Status.PENDENTE,
            created_by=request.user,
            attachment=attachment,
        )
        _notify_whatsapp(ticket, event_type="new_ticket", event_label="Novo chamado")
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
        if not is_ti:
            context['own_tickets'] = (
                Ticket.objects.filter(created_by=self.request.user).order_by('-created_at')
            )
            return context

        ti_users = list(ERPUser.objects.filter(department__iexact='TI', is_active=True).order_by('full_name'))
        context['ti_users'] = ti_users
        context['pending_tickets'] = Ticket.objects.filter(status=Ticket.Status.PENDENTE).select_related('created_by').order_by('-created_at')
        context['closed_tickets'] = Ticket.objects.filter(status=Ticket.Status.FECHADO).select_related('created_by').order_by('-created_at')
        in_progress_tickets = Ticket.objects.filter(status=Ticket.Status.EM_ATENDIMENTO).select_related('created_by').prefetch_related(
            'collaborators'
        )
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

        all_tickets = list(context['pending_tickets']) + list(context['closed_tickets']) + list(in_progress_tickets)
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
            }
        context['ticket_meta'] = ticket_meta

        context['user_tickets'] = ticket_map
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
    previous_status = ticket.status
    previous_assignee_id = ticket.assigned_to_id

    if target == 'pendente':
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

        # When the ticket is shared across attendants, dropping to pending from one
        # user column should remove only that attendant and keep the others working.
        if source_user_id and source_user_id in current_assignees and len(current_assignees) > 1:
            if ticket.assigned_to_id == source_user_id:
                remaining = [uid for uid in current_assignees if uid != source_user_id]
                promoted_id = remaining[0]
                ticket.assigned_to_id = promoted_id
                ticket.save(update_fields=['assigned_to', 'updated_at'])
                ticket.collaborators.remove(promoted_id)
            else:
                ticket.collaborators.remove(source_user_id)
            return JsonResponse({'ok': True, 'partial_unassign': True})

        ticket.status = Ticket.Status.PENDENTE
        ticket.assigned_to = None
        ticket.save()
        ticket.collaborators.clear()
        if previous_status != Ticket.Status.PENDENTE:
            _notify_whatsapp(ticket, event_type="status_pending", event_label="Status atualizado", extra_line="Status atual: Pendente")
            _notify_ticket_email(ticket, event_label="Status atualizado", extra_line="Status atual: Pendente")
        return JsonResponse({'ok': True})
    if target == 'fechado':
        resolution = (request.POST.get('resolution') or '').strip()
        if not resolution:
            return JsonResponse({'ok': False, 'error': 'resolution_required'}, status=400)
        ticket.status = Ticket.Status.FECHADO
        ticket.resolution = resolution
        ticket.save()
        if previous_status != Ticket.Status.FECHADO:
            _notify_whatsapp(ticket, event_type="status_closed", event_label="Status atualizado", extra_line="Status atual: Fechado")
            _notify_ticket_email(ticket, event_label="Status atualizado", extra_line="Status atual: Fechado")
        return JsonResponse({'ok': True})
    if target.startswith('user_'):
        user_id = target.replace('user_', '')
        assignee = ERPUser.objects.filter(id=user_id).first()
        if not assignee:
            return JsonResponse({'ok': False, 'error': 'user_not_found'}, status=404)
        ticket.status = Ticket.Status.EM_ATENDIMENTO
        sent_assignment = False
        if multi and ticket.assigned_to_id and ticket.assigned_to_id != assignee.id:
            ticket.save()
            ticket.collaborators.add(assignee)
        else:
            ticket.assigned_to = assignee
            ticket.save()
            ticket.collaborators.clear()
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
        return JsonResponse({'ok': True})

    return JsonResponse({'ok': False, 'error': 'invalid_target'}, status=400)


@login_required
@require_GET
def ticket_detail(request, ticket_id: int):
    ticket = (
        Ticket.objects.filter(id=ticket_id)
        .select_related('assigned_to', 'created_by')
        .prefetch_related('collaborators')
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
            'created_at': msg.created_at.strftime('%d/%m/%Y %H:%M'),
        }
        if msg.is_internal:
            internal_messages.append(payload)
        else:
            public_messages.append(payload)

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
            'assignees': ', '.join(
                [
                    name
                    for name in (
                        [ticket.assigned_to.full_name] if ticket.assigned_to else []
                    )
                    + [u.full_name for u in ticket.collaborators.all() if not ticket.assigned_to or u.id != ticket.assigned_to_id]
                ]
            )
            or '-',
            'attachment_url': ticket.attachment.url if ticket.attachment else '',
            'created_at': ticket.created_at.strftime('%d/%m/%Y %H:%M'),
            'can_edit': can_edit,
        },
        'messages': {
            'public': public_messages,
            'internal': internal_messages,
        },
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
        ticket.save(update_fields=['status', 'updated_at'])
        _notify_whatsapp(ticket, event_type="status_pending", event_label="Status atualizado", extra_line="Status atual: Pendente")
        _notify_ticket_email(ticket, event_label="Status atualizado", extra_line="Status atual: Pendente")
    return JsonResponse({'ok': True})

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




