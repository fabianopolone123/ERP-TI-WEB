from __future__ import annotations

import json
import logging
import subprocess
from datetime import datetime
from typing import Any

from django.utils import timezone

from .models import Equipment, SoftwareInventory

logger = logging.getLogger(__name__)


def _parse_memory_gb(memory_raw: Any) -> str:
    try:
        value = int(memory_raw or 0)
    except (TypeError, ValueError):
        return ''
    if value <= 0:
        return ''
    gb = round(value / (1024 ** 3))
    return f'{gb} GB'


def _parse_total_disk(disk_items: list[dict[str, Any]]) -> str:
    total = 0
    for item in disk_items or []:
        try:
            total += int(item.get('Size') or 0)
        except (TypeError, ValueError):
            continue
    if total <= 0:
        return ''
    gb = round(total / (1024 ** 3))
    return f'{gb} GB'


def _run_inventory_powershell(hostname: str, timeout_seconds: int = 120) -> dict[str, Any]:
    ps_script = rf"""
$ErrorActionPreference = 'Stop'
$computer = '{hostname}'

$cs = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $computer
$bios = Get-CimInstance -ClassName Win32_BIOS -ComputerName $computer
$cpu = Get-CimInstance -ClassName Win32_Processor -ComputerName $computer | Select-Object -First 1
$os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $computer
$disks = Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $computer -Filter "DriveType=3"

$softwareItems = @()
try {{
    $softwareItems = Get-CimInstance -ClassName Win32_Product -ComputerName $computer |
        Where-Object {{ $_.Name -and $_.Name.Trim().Length -gt 0 }} |
        Select-Object Name, Version, Vendor, InstallDate
}} catch {{
    $softwareItems = @()
}}

$result = [PSCustomObject]@{{
    Hostname = $computer
    UserName = $cs.UserName
    Model = $cs.Model
    Brand = $cs.Manufacturer
    Serial = $bios.SerialNumber
    Memory = $cs.TotalPhysicalMemory
    Processor = $cpu.Name
    HD = @($disks | Select-Object DeviceID, Size)
    Windows = $os.Caption
    Software = @($softwareItems)
}}

$result | ConvertTo-Json -Depth 6 -Compress
"""
    completed = subprocess.run(
        ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
        capture_output=True,
        text=True,
        timeout=max(30, int(timeout_seconds)),
        check=False,
    )

    if completed.returncode != 0:
        stderr = (completed.stderr or '').strip()
        stdout = (completed.stdout or '').strip()
        raise RuntimeError(stderr or stdout or f'Falha ao inventariar host {hostname}.')

    raw_output = (completed.stdout or '').strip()
    if not raw_output:
        raise RuntimeError(f'Saída vazia ao inventariar host {hostname}.')

    try:
        return json.loads(raw_output)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f'Retorno inválido do PowerShell para host {hostname}: {exc}') from exc


def _to_iso_br_date(raw_value: str) -> str:
    value = (raw_value or '').strip()
    if not value:
        return ''
    if len(value) == 8 and value.isdigit():
        yyyy = value[0:4]
        mm = value[4:6]
        dd = value[6:8]
        return f'{dd}/{mm}/{yyyy}'
    return value


def upsert_inventory_from_payload(payload: dict[str, Any], source: str = 'rede') -> tuple[bool, str]:
    now = timezone.now()

    host = (payload.get('Hostname') or '').strip()
    if not host:
        raise RuntimeError('Hostname não informado no payload.')
    user_raw = (payload.get('UserName') or '').strip()
    user_name = user_raw.split('\\')[-1].strip() if user_raw else ''
    sector = (payload.get('Sector') or '').strip()
    model = (payload.get('Model') or '').strip()
    brand = (payload.get('Brand') or '').strip()
    serial = (payload.get('Serial') or '').strip()
    processor = (payload.get('Processor') or '').strip()
    windows = (payload.get('Windows') or '').strip()
    memory = _parse_memory_gb(payload.get('Memory'))
    hd = _parse_total_disk(payload.get('HD') or [])

    equipment = (
        Equipment.objects.filter(hostname__iexact=host).first()
        or Equipment.objects.filter(serial__iexact=serial).first()
        or Equipment.objects.filter(user__iexact=user_name, model__iexact=model).first()
    )
    if equipment is None:
        equipment = Equipment(hostname=host)

    equipment.user = user_name or equipment.user
    equipment.sector = sector or equipment.sector
    equipment.equipment = equipment.equipment or 'Computador'
    equipment.model = model
    equipment.brand = brand
    equipment.serial = serial
    equipment.memory = memory
    equipment.processor = processor
    equipment.hd = hd
    equipment.windows = windows
    equipment.hostname = host
    equipment.inventory_source = source
    equipment.last_inventory_at = now
    equipment.save()

    software_items = payload.get('Software') or []
    SoftwareInventory.objects.filter(hostname__iexact=host).delete()

    new_items = []
    for item in software_items:
        name = (item.get('Name') or '').strip()
        if not name:
            continue
        new_items.append(
            SoftwareInventory(
                equipment=equipment,
                hostname=host,
                user=user_name,
                sector=equipment.sector,
                software_name=name,
                version=(item.get('Version') or '').strip(),
                vendor=(item.get('Vendor') or '').strip(),
                install_date=_to_iso_br_date(str(item.get('InstallDate') or '')),
                source=source,
                collected_at=now,
            )
        )

    if new_items:
        SoftwareInventory.objects.bulk_create(new_items)

    return True, f'{host}: {len(new_items)} software(s) atualizado(s).'


def _sync_single_host(hostname: str, timeout_seconds: int = 120) -> tuple[bool, str]:
    payload = _run_inventory_powershell(hostname=hostname, timeout_seconds=timeout_seconds)
    if not payload.get('Hostname'):
        payload['Hostname'] = hostname
    return upsert_inventory_from_payload(payload, source='rede')


def sync_network_inventory(hosts: list[str], timeout_seconds: int = 120) -> dict[str, Any]:
    normalized_hosts: list[str] = []
    seen: set[str] = set()
    for raw in hosts:
        item = (raw or '').strip()
        if not item:
            continue
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        normalized_hosts.append(item)

    result: dict[str, Any] = {
        'total': len(normalized_hosts),
        'ok': 0,
        'failed': 0,
        'messages': [],
    }

    for host in normalized_hosts:
        try:
            _, message = _sync_single_host(hostname=host, timeout_seconds=timeout_seconds)
            result['ok'] += 1
            result['messages'].append(message)
        except Exception as exc:
            logger.exception('Falha ao sincronizar inventário do host %s', host)
            result['failed'] += 1
            result['messages'].append(f'{host}: erro ({exc})')

    return result


def parse_hosts_text(raw_text: str) -> list[str]:
    if not raw_text:
        return []
    chunks = raw_text.replace(';', ',').replace('\n', ',').split(',')
    return [item.strip() for item in chunks if item.strip()]


def format_inventory_run_stamp() -> str:
    now = datetime.now()
    return now.strftime('%d/%m/%Y %H:%M:%S')
