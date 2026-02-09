from __future__ import annotations

import os
import re
import subprocess
import unicodedata

from django.conf import settings
from ldap3 import Connection, Server, SUBTREE
from ldap3.utils.conv import escape_filter_chars

from .models import AccessFolder, AccessGroup, AccessMember, ERPUser


_IGNORE_PREFIXES = (
    'BUILTIN\\',
    'NT AUTHORITY\\',
    'NT SERVICE\\',
)
_IGNORE_NAMES = {
    'CREATOR OWNER',
}
_GLOBAL_IDENTITY_NAMES = {
    'everyone',
    'authenticated users',
    'domain users',
    'todos',
    'usuarios autenticados',
    'usuarios do dominio',
}


def _connect_ad() -> Connection:
    server_uri = getattr(settings, 'AD_LDAP_SERVER_URI', '')
    base_dn = getattr(settings, 'AD_LDAP_BASE_DN', '')
    bind_dn = getattr(settings, 'AD_LDAP_BIND_DN', '')
    bind_password = getattr(settings, 'AD_LDAP_BIND_PASSWORD', '')
    if not server_uri or not base_dn:
        raise RuntimeError('Configuração LDAP incompleta.')
    server = Server(server_uri, get_info=None)
    return Connection(server, user=bind_dn, password=bind_password, auto_bind=True)


def _list_folders(root_path: str) -> list[tuple[str, str]]:
    folders = []
    for name in sorted(os.listdir(root_path)):
        full_path = os.path.join(root_path, name)
        if os.path.isdir(full_path):
            folders.append((name, full_path))
    return folders


def _parse_icacls(path: str) -> list[tuple[str, str]]:
    result = subprocess.run(
        ['icacls', path],
        capture_output=True,
        text=True,
        encoding='utf-8',
        errors='ignore',
        check=False,
    )
    identities: list[tuple[str, str]] = []
    for raw in result.stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.lower().startswith(path.lower()):
            line = line[len(path):].strip()
        if ':' not in line:
            continue
        identity, rights = line.split(':', 1)
        identity = identity.strip()
        rights = rights.strip()
        if not identity:
            continue
        identities.append((identity, rights))
    return identities


def _rights_to_level(rights: str) -> str:
    tokens = re.findall(r'\(([^)]+)\)', rights or '')
    joined = ''.join(tokens).upper()
    if any(flag in joined for flag in ('F', 'M', 'W', 'D', 'C')):
        return 'leitura_escrita'
    if 'R' in joined:
        return 'leitura'
    return 'leitura'


def _filter_group(identity: str) -> str | None:
    if any(identity.startswith(prefix) for prefix in _IGNORE_PREFIXES):
        return None
    if identity in _IGNORE_NAMES:
        return None
    if identity.endswith('$'):
        return None
    if '\\' in identity:
        return identity.split('\\', 1)[1]
    return identity


def _normalize_identity_name(value: str) -> str:
    raw = (value or '').strip().lower()
    no_accent = unicodedata.normalize('NFKD', raw).encode('ascii', 'ignore').decode('ascii')
    return no_accent


def _is_global_identity(identity: str) -> bool:
    base = identity.split('\\', 1)[1] if '\\' in identity else identity
    return _normalize_identity_name(base) in _GLOBAL_IDENTITY_NAMES


def _resolve_group_members(conn: Connection, group_name: str) -> list[tuple[str, str]]:
    base_dn = getattr(settings, 'AD_LDAP_BASE_DN', '')
    safe_group = escape_filter_chars(group_name)
    group_filter = f'(&(objectCategory=group)(cn={safe_group}))'
    conn.search(search_base=base_dn, search_filter=group_filter, search_scope=SUBTREE, attributes=['distinguishedName'])
    if not conn.entries:
        return []
    group_dn = conn.entries[0].distinguishedName.value
    safe_group_dn = escape_filter_chars(group_dn)
    user_filter = (
        '(&(objectCategory=person)(objectClass=user)'
        f'(memberOf:1.2.840.113556.1.4.1941:={safe_group_dn}))'
    )
    conn.search(
        search_base=base_dn,
        search_filter=user_filter,
        search_scope=SUBTREE,
        attributes=['sAMAccountName', 'displayName'],
    )
    members: list[tuple[str, str]] = []
    for entry in conn.entries:
        username = entry.sAMAccountName.value if 'sAMAccountName' in entry else ''
        display = entry.displayName.value if 'displayName' in entry else ''
        name = display or username or ''
        if name:
            members.append((name, username or ''))
    return members


def refresh_access_snapshot(root_path: str) -> tuple[int, int, int]:
    if not os.path.isdir(root_path):
        raise RuntimeError('Caminho das pastas não encontrado.')

    conn = _connect_ad()

    AccessMember.objects.all().delete()
    AccessGroup.objects.all().delete()
    AccessFolder.objects.all().delete()

    folders = _list_folders(root_path)
    group_count = 0
    member_count = 0
    active_users = list(ERPUser.objects.filter(is_active=True).order_by('full_name'))

    for folder_name, folder_path in folders:
        folder = AccessFolder.objects.create(name=folder_name, path=folder_path)
        identities = _parse_icacls(folder_path)
        group_levels: dict[str, str] = {}
        group_is_global: dict[str, bool] = {}
        for identity, rights in identities:
            group_name = _filter_group(identity)
            is_global = False
            if not group_name and _is_global_identity(identity):
                group_name = 'Todos os usuarios'
                is_global = True
            if not group_name:
                continue
            level = _rights_to_level(rights)
            current = group_levels.get(group_name)
            if current == 'leitura_escrita':
                continue
            if level == 'leitura_escrita' or current is None:
                group_levels[group_name] = level
            group_is_global[group_name] = group_is_global.get(group_name, False) or is_global

        for group_name, level in group_levels.items():
            group = AccessGroup.objects.create(folder=folder, name=group_name, access_level=level)
            group_count += 1
            if group_is_global.get(group_name):
                members = [(u.full_name or u.username or '', u.username or '') for u in active_users]
            else:
                members = _resolve_group_members(conn, group_name)
            member_objs = [AccessMember(group=group, name=name, username=username) for name, username in members]
            if member_objs:
                AccessMember.objects.bulk_create(member_objs)
                member_count += len(member_objs)

    conn.unbind()
    return len(folders), group_count, member_count
