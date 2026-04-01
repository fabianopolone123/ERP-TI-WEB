from __future__ import annotations

from time import time
from django.utils import timezone

from .audit import describe_request, log_audit_event


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
