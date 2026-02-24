from __future__ import annotations

from django.utils import timezone

from .audit import describe_request, log_audit_event


class AuditTrailMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        path = (getattr(request, 'path', '') or '')
        if path.startswith('/static/') or path.startswith('/media/'):
            return response
        if path in {'/ws/tickets/'}:
            return response

        # Skip unauthenticated requests except logout/login POST if already authenticated state is present.
        user = getattr(request, 'user', None)
        if not (user and getattr(user, 'is_authenticated', False)):
            return response

        method = (getattr(request, 'method', '') or '').upper()
        if method not in {'GET', 'POST'}:
            return response

        # Reduce noise from rapid refresh loops: dedupe same GET path in a short interval per session.
        if method == 'GET':
            try:
                key = '_audit_last_access'
                current_ts = timezone.now().timestamp()
                last = request.session.get(key) or {}
                if last.get('path') == path and (current_ts - float(last.get('ts') or 0)) < 20:
                    return response
                request.session[key] = {'path': path, 'ts': current_ts}
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
