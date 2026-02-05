from __future__ import annotations

from typing import Any

from django.conf import settings
from django.contrib.auth import get_user_model
from ldap3 import Connection, Server, SUBTREE


class ActiveDirectoryBackend:
    """Autentica no AD via LDAP (sem python-ldap)."""

    def authenticate(self, request, username: str | None = None, password: str | None = None, **kwargs: Any):
        if not username or not password:
            return None

        server_uri = getattr(settings, 'AD_LDAP_SERVER_URI', '')
        base_dn = getattr(settings, 'AD_LDAP_BASE_DN', '')
        bind_dn = getattr(settings, 'AD_LDAP_BIND_DN', '')
        bind_password = getattr(settings, 'AD_LDAP_BIND_PASSWORD', '')
        user_filter = getattr(settings, 'AD_LDAP_USER_FILTER', '')
        user_attr_map = getattr(settings, 'AD_LDAP_USER_ATTR_MAP', {})

        if not server_uri or not base_dn or not user_filter:
            return None

        server = Server(server_uri, get_info=None)
        conn = Connection(server, user=bind_dn, password=bind_password, auto_bind=True)
        search_filter = user_filter.replace('%(user)s', username)
        conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=list(user_attr_map.values()))
        if not conn.entries:
            conn.unbind()
            return None

        entry = conn.entries[0]
        user_dn = entry.entry_dn
        conn.unbind()

        # Verifica senha do usuário no AD
        user_conn = Connection(server, user=user_dn, password=password, auto_bind=True)
        user_conn.unbind()

        User = get_user_model()
        user, _created = User.objects.get_or_create(username=username)

        for field, ldap_attr in user_attr_map.items():
            if hasattr(user, field) and ldap_attr in entry:
                value = entry[ldap_attr].value
                if value is not None:
                    setattr(user, field, value)

        user.set_unusable_password()
        user.save()
        return user

    def get_user(self, user_id: int):
        User = get_user_model()
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
