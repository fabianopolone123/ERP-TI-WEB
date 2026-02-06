from __future__ import annotations

import re
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


def _last4_digits(value: str) -> str:
    if not value:
        return ''
    digits = re.sub(r'\D', '', value)
    return digits[-4:] if len(digits) >= 4 else digits


def _format_br_phone(value: str) -> str:
    if not value:
        return ''
    digits = re.sub(r'\D', '', value)
    if len(digits) == 11:
        return f'({digits[:2]}) {digits[2:7]}-{digits[7:]}'
    if len(digits) == 10:
        return f'({digits[:2]}) {digits[2:6]}-{digits[6:]}'
    return value.strip()


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
        department = entry[attr_map['department']].value if attr_map.get('department') in entry else ''
        guid_val = entry[attr_map['guid']].value if attr_map.get('guid') in entry else None
        active_val = entry[attr_map['active']].value if attr_map.get('active') in entry else None
        phone_raw = entry[attr_map['phone']].value if attr_map.get('phone') in entry else ''
        mobile_raw = entry[attr_map['mobile']].value if attr_map.get('mobile') in entry else ''
        email = entry[attr_map['email']].value if attr_map.get('email') in entry else ''

        if not username:
            continue

        guid = _guid_to_str(guid_val)
        is_active = _is_active_from_uac(active_val)
        phone = _format_br_phone(phone_raw)
        mobile = _format_br_phone(mobile_raw)
        extension = _last4_digits(phone_raw)

        defaults = {
            'full_name': full_name or username,
            'department': department or '',
            'phone': phone or '',
            'mobile': mobile or '',
            'email': email or '',
            'extension': extension,
            'is_active': is_active,
            'username': username,
            'ad_guid': guid or '',
        }

        existing = None
        if guid:
            existing = ERPUser.objects.filter(ad_guid=guid).first()
        if existing is None:
            existing = ERPUser.objects.filter(username=username).first()

        if existing is None:
            ERPUser.objects.create(**defaults)
            created += 1
            continue

        changed = False
        for field, value in defaults.items():
            if getattr(existing, field) != value:
                setattr(existing, field, value)
                changed = True
        if changed:
            existing.save()
            updated += 1

    conn.unbind()
    return created, updated
