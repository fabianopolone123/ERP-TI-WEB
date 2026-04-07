from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from core.models import ERPUser, Ticket, TicketAttendantCycle, TicketTimelineEvent, TicketWorkLog
from core.views import _sync_ticket_cycle_snapshot


AUTO_PAUSE_NOTE = 'Pausa automatica de encerramento do dia. Registrar resolucao manual depois.'


class Command(BaseCommand):
    help = (
        'Tira do play os chamados em execucao dos atendentes marcados para '
        'auto-pausa no fim do expediente e sinaliza pendencia de resolucao manual.'
    )

    def add_arguments(self, parser):
        parser.add_argument(
            '--username',
            action='append',
            default=[],
            help='Limita a execucao a um ou mais usernames do ERPUser.',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Somente mostra o que seria pausado, sem gravar alteracoes.',
        )

    def handle(self, *args, **options):
        usernames = [(item or '').strip().lower() for item in (options.get('username') or []) if (item or '').strip()]
        dry_run = bool(options.get('dry_run'))
        now_dt = timezone.now()
        valid_failures = {choice[0] for choice in Ticket.FailureType.choices}

        attendants_qs = ERPUser.objects.filter(
            department__iexact='TI',
            is_active=True,
            auto_pause_play_tickets_at_end_of_day=True,
        ).order_by('full_name')
        attendants = list(attendants_qs)
        if usernames:
            wanted = set(usernames)
            attendants = [item for item in attendants if ((item.username or '').strip().lower() in wanted)]

        attendant_ids = [item.id for item in attendants]
        if not attendant_ids:
            self.stdout.write('Nenhum atendente configurado para auto-pausa.')
            return

        cycles = list(
            TicketAttendantCycle.objects.select_related('ticket', 'attendant')
            .filter(attendant_id__in=attendant_ids, current_cycle_started_at__isnull=False)
            .exclude(ticket__status__in=[Ticket.Status.FECHADO, Ticket.Status.CANCELADO])
            .order_by('attendant__full_name', 'ticket_id')
        )

        if not cycles:
            self.stdout.write('Nenhum chamado em play para auto-pausar.')
            return

        self.stdout.write(
            f'Atendentes alvo: {len(attendant_ids)} | chamados em play encontrados: {len(cycles)}'
        )

        paused_count = 0
        changed_tickets: set[int] = set()

        for cycle in cycles:
            ticket = cycle.ticket
            attendant = cycle.attendant
            preview = f'#{ticket.id} - {ticket.title} | {attendant.full_name}'
            if dry_run:
                self.stdout.write(f'[dry-run] {preview}')
                continue

            with transaction.atomic():
                locked_cycle = (
                    TicketAttendantCycle.objects.select_for_update()
                    .select_related('ticket', 'attendant')
                    .filter(id=cycle.id)
                    .first()
                )
                if not locked_cycle or not locked_cycle.current_cycle_started_at:
                    continue

                locked_ticket = locked_cycle.ticket
                failure_type = (locked_ticket.last_failure_type or '').strip()
                if failure_type not in valid_failures:
                    failure_type = Ticket.FailureType.NA

                TicketWorkLog.objects.create(
                    ticket=locked_ticket,
                    attendant=locked_cycle.attendant,
                    opened_at=locked_cycle.current_cycle_started_at,
                    closed_at=now_dt,
                    failure_type=failure_type,
                    action_text=AUTO_PAUSE_NOTE,
                    priority_label=locked_ticket.get_urgency_display(),
                )

                previous_status = locked_ticket.status
                locked_cycle.current_cycle_started_at = None
                locked_cycle.manual_resolution_pending = True
                locked_cycle.manual_resolution_pending_since = now_dt
                locked_cycle.save(
                    update_fields=[
                        'current_cycle_started_at',
                        'manual_resolution_pending',
                        'manual_resolution_pending_since',
                        'updated_at',
                    ]
                )

                has_running_cycles = TicketAttendantCycle.objects.filter(
                    ticket=locked_ticket,
                    current_cycle_started_at__isnull=False,
                ).exists()
                ticket_update_fields = ['last_failure_type', 'updated_at']
                locked_ticket.last_failure_type = failure_type
                if not has_running_cycles and locked_ticket.status not in {Ticket.Status.FECHADO, Ticket.Status.CANCELADO}:
                    locked_ticket.status = Ticket.Status.PENDENTE
                    if 'status' not in ticket_update_fields:
                        ticket_update_fields.append('status')
                locked_ticket.save(update_fields=ticket_update_fields)
                _sync_ticket_cycle_snapshot(locked_ticket)

                TicketTimelineEvent.objects.create(
                    ticket=locked_ticket,
                    event_type=TicketTimelineEvent.EventType.STATUS_CHANGED,
                    from_status=previous_status,
                    to_status=locked_ticket.status,
                    note=(
                        'Atendimento pausado automaticamente no fim do expediente para '
                        f'{locked_cycle.attendant.full_name}. Resolucao manual pendente.'
                    ),
                )

            paused_count += 1
            changed_tickets.add(ticket.id)
            self.stdout.write(self.style.SUCCESS(f'Auto-pausado: {preview}'))

        if dry_run:
            self.stdout.write(self.style.SUCCESS('Dry-run concluido sem alteracoes.'))
            return

        self.stdout.write(
            self.style.SUCCESS(
                f'Concluido: {paused_count} ciclo(s) pausado(s) em {len(changed_tickets)} chamado(s).'
            )
        )
