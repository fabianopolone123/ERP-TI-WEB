from __future__ import annotations

import uuid

from django.conf import settings
from ldap3 import Connection, Server, SUBTREE

from .models import ERPUser


def _guid_to_str(value) -> str:
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, bytes):
        return str(uuid.UUID(bytes=value))
    if value is None:
        return ''
    return str(value)


def _is_active_from_uac(uac_value) -> bool:
    try:
        uac = int(uac_value)
    except (TypeError, ValueError):
        return True
    return (uac & 2) == 0


def import_ad_users() -> tuple[int, int]:
    server_uri = getattr(settings, 'AD_LDAP_SERVER_URI', '')
    base_dn = getattr(settings, 'AD_LDAP_BASE_DN', '')
    bind_dn = getattr(settings, 'AD_LDAP_BIND_DN', '')
    bind_password = getattr(settings, 'AD_LDAP_BIND_PASSWORD', '')
    user_filter = getattr(settings, 'AD_LDAP_IMPORT_FILTER', '')
    attr_map = getattr(settings, 'AD_LDAP_IMPORT_ATTR_MAP', {})

    if not server_uri or not base_dn or not user_filter:
        raise RuntimeError('Configuração LDAP incompleta.')

    server = Server(server_uri, get_info=None)
    conn = Connection(server, user=bind_dn, password=bind_password, auto_bind=True)
    attributes = list(set(attr_map.values()))
    conn.search(search_base=base_dn, search_filter=user_filter, search_scope=SUBTREE, attributes=attributes)

    created = 0
    updated = 0

    for entry in conn.entries:
        username = entry[attr_map['username']].value if attr_map.get('username') in entry else None
        full_name = entry[attr_map['full_name']].value if attr_map.get('full_name') in entry else None
        role = entry[attr_map['role']].value if attr_map.get('role') in entry else ''
        department = entry[attr_map['department']].value if attr_map.get('department') in entry else ''
        guid_val = entry[attr_map['guid']].value if attr_map.get('guid') in entry else None
        active_val = entry[attr_map['active']].value if attr_map.get('active') in entry else None

        if not username:
            continue

        guid = _guid_to_str(guid_val)
        is_active = _is_active_from_uac(active_val)

        defaults = {
            'full_name': full_name or username,
            'role': role or '',
            'department': department or '',
            'is_active': is_active,
        }

        if guid:
            user, was_created = ERPUser.objects.update_or_create(ad_guid=guid, defaults={**defaults, 'username': username})
        else:
            user, was_created = ERPUser.objects.update_or_create(username=username, defaults={**defaults, 'ad_guid': ''})

        if was_created:
            created += 1
        else:
            updated += 1

    conn.unbind()
    return created, updated
