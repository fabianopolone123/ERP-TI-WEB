from django.conf import settings
from django.core.management.base import BaseCommand

from core.network_inventory import parse_hosts_text, sync_network_inventory


class Command(BaseCommand):
    help = 'Sincroniza inventário de equipamentos e softwares da rede.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--hosts',
            default='',
            help='Hosts separados por vírgula. Se vazio, usa INVENTORY_DEFAULT_HOSTS do .env.',
        )
        parser.add_argument(
            '--timeout',
            type=int,
            default=None,
            help='Timeout por host em segundos.',
        )

    def handle(self, *args, **options):
        hosts_raw = (options.get('hosts') or '').strip()
        default_hosts = (getattr(settings, 'INVENTORY_DEFAULT_HOSTS', '') or '').strip()
        hosts = parse_hosts_text(hosts_raw) or parse_hosts_text(default_hosts)
        if not hosts:
            self.stderr.write('Nenhum host informado. Configure INVENTORY_DEFAULT_HOSTS ou use --hosts.')
            return

        timeout_seconds = options.get('timeout') or int(getattr(settings, 'INVENTORY_POWERSHELL_TIMEOUT', 120) or 120)
        self.stdout.write(f'Iniciando inventário para {len(hosts)} host(s)...')
        result = sync_network_inventory(hosts=hosts, timeout_seconds=timeout_seconds)

        for line in result.get('messages', []):
            if 'erro' in line.lower():
                self.stderr.write(line)
            else:
                self.stdout.write(line)

        self.stdout.write(
            self.style.SUCCESS(
                f'Concluído: {result["ok"]} sucesso(s), {result["failed"]} falha(s), total {result["total"]} host(s).'
            )
        )
