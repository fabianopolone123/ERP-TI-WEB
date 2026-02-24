from __future__ import annotations

from typing import Any

from django.utils import timezone

from .models import AuditLog


def _client_ip(request) -> str:
    xff = (request.META.get('HTTP_X_FORWARDED_FOR') or '').strip()
    if xff:
        return xff.split(',')[0].strip()
    return (request.META.get('REMOTE_ADDR') or '').strip()


def log_audit_event(*, request=None, user=None, event_type: str = 'action', description: str, details: str = '', status_code: int = 0, route_name: str = '', path: str = '', method: str = '') -> AuditLog:
    actor = user or getattr(request, 'user', None)
    username = ''
    full_name = ''
    user_obj = None
    if actor is not None and getattr(actor, 'is_authenticated', False):
        user_obj = actor
        username = (getattr(actor, 'username', '') or '').strip()
        full_name = (getattr(actor, 'get_full_name', lambda: '')() or '').strip()
    return AuditLog.objects.create(
        user=user_obj,
        username=username,
        full_name=full_name,
        event_type=event_type or AuditLog.EventType.ACTION,
        method=(method or getattr(request, 'method', '') or '')[:10],
        path=(path or getattr(request, 'path', '') or '')[:300],
        route_name=(route_name or getattr(getattr(request, 'resolver_match', None), 'url_name', '') or '')[:120],
        status_code=int(status_code or 0),
        description=(description or 'Evento')[:300],
        details=details or '',
        ip_address=(_client_ip(request) if request is not None else '')[:64],
    )


def describe_request(request, response=None) -> tuple[str, str, str]:
    method = (getattr(request, 'method', '') or '').upper()
    route_name = (getattr(getattr(request, 'resolver_match', None), 'url_name', '') or '').strip()
    path = (getattr(request, 'path', '') or '').strip()
    action = (request.POST.get('action') or '').strip() if method == 'POST' else ''

    labels = {
        'chamados': 'Chamados',
        'usuarios': 'Usuarios',
        'acessos': 'Acessos',
        'equipamentos': 'Equipamentos',
        'softwares': 'Softwares',
        'requisicoes': 'Requisicoes',
        'dicas': 'Dicas',
        'relatorios': 'Relatorios',
        'auditoria': 'Auditoria',
    }

    if method == 'GET':
        if route_name in labels:
            return ('access', f'Acessou {labels[route_name]}', '')
        if route_name == 'dashboard':
            return ('access', 'Acessou pagina inicial', '')
        return ('access', f'Acessou {path or route_name or "pagina"}', '')

    if method == 'POST':
        if route_name == 'equipamentos':
            mapping = {
                'create': 'Cadastrou equipamento',
                'update': 'Editou equipamento',
                'reconcile_inventory': 'Vinculou inventario a etiqueta',
                'sync_inventory': 'Executou sincronizacao de inventario',
                'delete': 'Tentou excluir equipamento (bloqueado)',
            }
            desc = mapping.get(action, 'Executou acao em Equipamentos')
            extra = ''
            if action == 'reconcile_inventory':
                extra = f"pendente_id={request.POST.get('pending_equipment_id','')} -> etiqueta={request.POST.get('target_tag_code','')}"
            elif action in {'create', 'update'}:
                extra = f"etiqueta={request.POST.get('tag_code','')} host={request.POST.get('hostname','')}"
            return ('action', desc, extra)
        if route_name in labels:
            return ('action', f'Executou acao em {labels[route_name]}', f'action={action}' if action else '')
        if route_name and route_name.startswith('chamados_'):
            return ('action', f'Acao em chamados ({route_name})', f'action={action}' if action else '')
        if route_name == 'logout':
            return ('action', 'Saiu do sistema', '')
        return ('action', f'POST {path or route_name}', f'action={action}' if action else '')

    return ('access', f'{method} {path or route_name}', '')
