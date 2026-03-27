from __future__ import annotations

from time import time
from django.conf import settings
from django.contrib.auth import logout
from django.shortcuts import redirect
from django.urls import reverse
from django.utils import timezone

from .audit import describe_request, log_audit_event
from .models import ERPUser


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
        if key and key not in seen:
            seen.add(key)
            uniq.append(item)
    return uniq


def _is_ti_authenticated_request(request) -> bool:
    user = getattr(request, 'user', None)
    if not (user and getattr(user, 'is_authenticated', False)):
        return False
    username = (getattr(user, 'username', '') or '').strip()
    if not username:
        return False

    session = getattr(request, 'session', None)
    if session is None:
        return False

    cached_username = session.get('ti_cache_username')
    cached_is_ti = session.get('ti_cache_is_ti')
    if cached_username == username and isinstance(cached_is_ti, bool):
        return cached_is_ti

    candidates = _username_candidates(username)
    is_ti = False
    for candidate in candidates:
        if ERPUser.objects.filter(
            username__iexact=candidate,
            department__iexact='TI',
            is_active=True,
        ).exists():
            is_ti = True
            break
    session['ti_cache_username'] = username
    session['ti_cache_is_ti'] = bool(is_ti)
    return bool(is_ti)


class TISessionHardeningMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = (getattr(request, 'path', '') or '')
        if (
            path.startswith('/static/')
            or path.startswith('/media/')
            or path.startswith('/login')
            or path.startswith('/logout')
        ):
            return self.get_response(request)

        if not _is_ti_authenticated_request(request):
            return self.get_response(request)

        raw_minutes = getattr(settings, 'TI_SESSION_IDLE_MINUTES', 20)
        try:
            idle_minutes = int(raw_minutes or 20)
        except (TypeError, ValueError):
            idle_minutes = 20
        if idle_minutes <= 0:
            return self.get_response(request)
        idle_minutes = min(idle_minutes, 480)

        raw_grace = getattr(settings, 'TI_SESSION_ACTIVITY_GRACE_SECONDS', 15)
        try:
            grace_seconds = int(raw_grace or 15)
        except (TypeError, ValueError):
            grace_seconds = 15
        grace_seconds = max(5, min(grace_seconds, 120))

        now_ts = int(time())
        last_activity_raw = request.session.get('ti_last_activity_ts')
        try:
            last_activity_ts = int(last_activity_raw or 0)
        except (TypeError, ValueError):
            last_activity_ts = 0

        if last_activity_ts and (now_ts - last_activity_ts) > (idle_minutes * 60):
            logout(request)
            return redirect(f"{reverse('login')}?session_expired=1")

        if not last_activity_ts or (now_ts - last_activity_ts) >= grace_seconds:
            request.session['ti_last_activity_ts'] = now_ts

        return self.get_response(request)


class AuditTrailMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self._recent_gets = {}

    def __call__(self, request):
        response = self.get_response(request)

        path = (getattr(request, 'path', '') or '')
        if path.startswith('/static/') or path.startswith('/media/'):
            return response
        if path in {'/ws/tickets/', '/favicon.ico'}:
            return response
        if path.startswith('/login') or path.startswith('/logout'):
            return response

        # Skip unauthenticated requests except logout/login POST if already authenticated state is present.
        user = getattr(request, 'user', None)
        if not (user and getattr(user, 'is_authenticated', False)):
            return response

        method = (getattr(request, 'method', '') or '').upper()
        if method not in {'GET', 'POST'}:
            return response

        # Reduce noise from rapid refresh loops without writing to session (avoids extra DB locks on SQLite).
        if method == 'GET':
            try:
                user_id = getattr(user, 'id', None) or 0
                dedupe_key = (int(user_id), path)
                current_ts = time()
                last_ts = float(self._recent_gets.get(dedupe_key) or 0)
                if (current_ts - last_ts) < 20:
                    return response
                self._recent_gets[dedupe_key] = current_ts
                if len(self._recent_gets) > 5000:
                    cutoff = current_ts - 120
                    self._recent_gets = {k: v for k, v in self._recent_gets.items() if v >= cutoff}
            except Exception:
                pass

        event_type, description, details = describe_request(request, response=response)
        try:
            log_audit_event(
                request=request,
                event_type=event_type,
                description=description,
                details=details,
                status_code=getattr(response, 'status_code', 0) or 0,
            )
        except Exception:
            # Auditoria nao pode derrubar o sistema
            pass
        return response
