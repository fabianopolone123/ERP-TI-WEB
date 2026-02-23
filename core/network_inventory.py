from __future__ import annotations

import json
import logging
import re
import subprocess
from datetime import datetime
from typing import Any

from django.utils import timezone

from .models import Equipment, SoftwareInventory, next_equipment_tag_code

logger = logging.getLogger(__name__)



def _norm_identifier(value: Any) -> str:
    return str(value or '').strip().upper()


def _norm_hostname(value: Any) -> str:
    return str(value or '').strip().lower()


def _norm_mac(value: Any) -> str:
    raw = str(value or '').strip().upper()
    return re.sub(r'[^0-9A-F]', '', raw)


def _parse_payload_mac_addresses(payload: dict[str, Any]) -> list[str]:
    raw_items = payload.get('MacAddresses') or payload.get('MACAddresses') or []
    values: list[str] = []
    if isinstance(raw_items, str):
        raw_items = re.split(r'[;,\n]+', raw_items)
    if isinstance(raw_items, list):
        for item in raw_items:
            if isinstance(item, dict):
                item = item.get('MacAddress') or item.get('MACAddress') or item.get('Address') or ''
            mac = _norm_mac(item)
            if mac and mac not in values:
                values.append(mac)
    return values


def _split_lines_unique(raw_text: str) -> list[str]:
    items: list[str] = []
    for line in (raw_text or '').replace(';', '\n').splitlines():
        token = line.strip()
        if token and token not in items:
            items.append(token)
    return items


def _merge_hostname_aliases(existing_aliases: str, old_hostname: str, new_hostname: str) -> str:
    aliases = _split_lines_unique(existing_aliases)
    old_host = (old_hostname or '').strip()
    new_host_norm = _norm_hostname(new_hostname)
    if old_host and _norm_hostname(old_host) != new_host_norm and old_host not in aliases:
        aliases.append(old_host)
    aliases = [a for a in aliases if _norm_hostname(a) != new_host_norm]
    return '\n'.join(aliases)


def _merge_mac_addresses(existing_macs: str, payload_macs: list[str]) -> str:
    normalized_existing = [_norm_mac(item) for item in _split_lines_unique(existing_macs)]
    values: list[str] = []
    for mac in normalized_existing + payload_macs:
        if mac and mac not in values:
            values.append(mac)
    return '\n'.join(values)


def _find_equipment_by_inventory_identifiers(
    host: str,
    bios_uuid: str,
    bios_serial: str,
    baseboard_serial: str,
    mac_addresses: list[str],
    serial: str,
    model: str,
    user_name: str,
) -> Equipment | None:
    if bios_uuid:
        equipment = Equipment.objects.filter(bios_uuid__iexact=bios_uuid).first()
        if equipment:
            return equipment

    if bios_serial:
        equipment = (
            Equipment.objects.filter(bios_serial__iexact=bios_serial).first()
            or Equipment.objects.filter(serial__iexact=bios_serial).first()
        )
        if equipment:
            return equipment

    if baseboard_serial:
        equipment = Equipment.objects.filter(baseboard_serial__iexact=baseboard_serial).first()
        if equipment:
            return equipment

    if mac_addresses:
        for equipment in Equipment.objects.exclude(mac_addresses='').only('id', 'mac_addresses'):
            existing = {_norm_mac(item) for item in _split_lines_unique(equipment.mac_addresses)}
            if existing.intersection(mac_addresses):
                return equipment

    host_norm = _norm_hostname(host)
    if host_norm:
        equipment = Equipment.objects.filter(hostname__iexact=host).first()
        if equipment:
            return equipment
        for equipment in Equipment.objects.exclude(hostname_aliases='').only('id', 'hostname_aliases'):
            aliases = {_norm_hostname(item) for item in _split_lines_unique(equipment.hostname_aliases)}
            if host_norm in aliases:
                return equipment

    if serial:
        equipment = Equipment.objects.filter(serial__iexact=serial).first()
        if equipment:
            return equipment

    if user_name and model:
        equipment = Equipment.objects.filter(user__iexact=user_name, model__iexact=model).first()
        if equipment:
            return equipment

    return None



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


def _infer_cpu_generation(processor_name: str, payload_generation: str = '') -> str:
    direct = (payload_generation or '').strip()
    if direct:
        return direct
    name = (processor_name or '').strip()
    if not name:
        return ''
    ultra_match = re.search(r'core\s*(?:\(\s*tm\s*\)\s*)?ultra\s*[3579]?\s*([0-9]{3,5})', name, flags=re.IGNORECASE)
    if ultra_match:
        digits = ultra_match.group(1)
        if len(digits) >= 5:
            return f'{digits[:2]}a'
        if len(digits) >= 3:
            return f'{digits[:1]}a'
    intel_match = re.search(r'i[3579]-([0-9]{4,5})', name, flags=re.IGNORECASE)
    if intel_match:
        digits = intel_match.group(1)
        if len(digits) == 5:
            return f'{digits[:2]}a'
        return f'{digits[:1]}a'
    intel_legacy_match = re.search(
        r'i[3579](?:\s*-\s*|\s+cpu\s+|\s+)(?:[a-z]{0,2}\s*)?([0-9]{3,5})[a-z]{0,2}\b',
        name,
        flags=re.IGNORECASE,
    )
    if intel_legacy_match:
        digits = intel_legacy_match.group(1)
        if len(digits) == 3:
            return '1a'
        if len(digits) >= 5:
            return f'{digits[:2]}a'
        return f'{digits[:1]}a'
    ryzen_match = re.search(r'ryzen\s+\d\s+([0-9]{4,5})', name, flags=re.IGNORECASE)
    if ryzen_match:
        digits = ryzen_match.group(1)
        return f'{digits[:1]}a'
    if re.search(r'core\s*(?:\(\s*tm\s*\)\s*)?2\b', name, flags=re.IGNORECASE):
        return 'Legado (Core 2)'
    if re.search(r'\bpentium\b|\bceleron\b|\bxeon\b', name, flags=re.IGNORECASE):
        return 'Legado'
    return ''


def _infer_mod_hd(payload: dict[str, Any], payload_mod_hd: str = '') -> str:
    direct = (payload_mod_hd or '').strip()
    if direct:
        return direct
    texts: list[str] = []
    numbers: list[str] = []

    physical = payload.get('PhysicalDisks') or []
    if isinstance(physical, list):
        for item in physical:
            if not isinstance(item, dict):
                continue
            for key in ('Model', 'MediaType', 'InterfaceType'):
                value = item.get(key)
                if isinstance(value, str) and value.strip():
                    texts.append(value.strip())

    physical_ex = payload.get('PhysicalDisksEx') or []
    if isinstance(physical_ex, list):
        for item in physical_ex:
            if not isinstance(item, dict):
                continue
            for key in ('FriendlyName', 'MediaType', 'BusType'):
                value = item.get(key)
                if isinstance(value, str) and value.strip():
                    texts.append(value.strip())
            spindle = item.get('SpindleSpeed')
            if spindle is not None:
                numbers.append(str(spindle))

    joined = ' '.join(texts).lower()
    if 'nvme' in joined:
        return 'SSD NVMe (M.2)'
    if 'ssd' in joined or 'solid state' in joined:
        return 'SSD'
    if 'hdd' in joined:
        return 'HDD'
    for number in numbers:
        try:
            if int(float(number)) > 0:
                return 'HDD'
        except (TypeError, ValueError):
            continue
    return 'Nao identificado'


def _run_inventory_powershell(hostname: str, timeout_seconds: int = 120) -> dict[str, Any]:
    ps_script = rf"""
$ErrorActionPreference = 'Stop'
$computer = '{hostname}'

$cs = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $computer
$bios = Get-CimInstance -ClassName Win32_BIOS -ComputerName $computer
$csProduct = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ComputerName $computer
$baseboard = Get-CimInstance -ClassName Win32_BaseBoard -ComputerName $computer | Select-Object -First 1
$cpu = Get-CimInstance -ClassName Win32_Processor -ComputerName $computer | Select-Object -First 1
$os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $computer
$disks = Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $computer -Filter "DriveType=3"
$physicalDisks = @()
try {{
    $physicalDisks = Get-CimInstance -ClassName Win32_DiskDrive -ComputerName $computer | Select-Object Model, MediaType, InterfaceType
}} catch {{
    $physicalDisks = @()
}}
$physicalDisksEx = @()
$macAddresses = @()
try {{
    $macAddresses = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ComputerName $computer |
        Where-Object {{ $_.IPEnabled -eq $true -and $_.MACAddress }} |
        Select-Object -ExpandProperty MACAddress
}} catch {{
    $macAddresses = @()
}}
try {{
    $session = New-CimSession -ComputerName $computer
    if (Get-Command Get-PhysicalDisk -ErrorAction SilentlyContinue) {{
        $physicalDisksEx = Get-PhysicalDisk -CimSession $session | Select-Object FriendlyName, MediaType, BusType, SpindleSpeed
    }}
    if ($session) {{
        $session | Remove-CimSession
    }}
}} catch {{
    $physicalDisksEx = @()
}}

$cpuGeneration = ''
if ($cpu.Name -match 'Core\\s*(\\(\\s*TM\\s*\\)\\s*)?Ultra\\s*[3579]?\\s*([0-9]{3,5})') {{
    $digits = $Matches[2]
    if ($digits.Length -ge 5) {{
        $cpuGeneration = \"{0}a\" -f $digits.Substring(0,2)
    }} elseif ($digits.Length -ge 3) {{
        $cpuGeneration = \"{0}a\" -f $digits.Substring(0,1)
    }}
}} elseif ($cpu.Name -match 'i[3579]-([0-9]{4,5})') {{
    $digits = $Matches[1]
    if ($digits.Length -ge 5) {{
        $cpuGeneration = \"{0}a\" -f $digits.Substring(0,2)
    }} else {{
        $cpuGeneration = \"{0}a\" -f $digits.Substring(0,1)
    }}
}} elseif ($cpu.Name -match 'i[3579](\\s*-\\s*|\\s+cpu\\s+|\\s+)([A-Za-z]{0,2}\\s*)?([0-9]{3,5})[A-Za-z]{0,2}\\b') {{
    $digits = $Matches[3]
    if ($digits.Length -eq 3) {{
        $cpuGeneration = '1a'
    }} elseif ($digits.Length -ge 5) {{
        $cpuGeneration = \"{0}a\" -f $digits.Substring(0,2)
    }} else {{
        $cpuGeneration = \"{0}a\" -f $digits.Substring(0,1)
    }}
}} elseif ($cpu.Name -match 'Ryzen\\s+\\d\\s+([0-9]{4,5})') {{
    $digits = $Matches[1]
    $cpuGeneration = \"{0}a\" -f $digits.Substring(0,1)
}} elseif ($cpu.Name -match 'core\\s*(\\(\\s*tm\\s*\\)\\s*)?2\\b') {{
    $cpuGeneration = 'Legado (Core 2)'
}} elseif ($cpu.Name -match '\\b(Pentium|Celeron|Xeon)\\b') {{
    $cpuGeneration = 'Legado'
}}

$diskType = 'Nao identificado'
$joinedDisks = (@($physicalDisks | ForEach-Object {{ ($_.Model + ' ' + $_.MediaType + ' ' + $_.InterfaceType) }}) -join ' ').ToLower()
$joinedDisksEx = (@($physicalDisksEx | ForEach-Object {{ ($_.FriendlyName + ' ' + $_.MediaType + ' ' + $_.BusType + ' ' + $_.SpindleSpeed) }}) -join ' ').ToLower()
$joinedAll = ($joinedDisks + ' ' + $joinedDisksEx).Trim()
if ($joinedAll -match 'nvme') {{
    $diskType = 'SSD NVMe (M.2)'
}} elseif ($joinedAll -match 'ssd|solid state') {{
    $diskType = 'SSD'
}} elseif ($joinedAll -match 'hdd') {{
    $diskType = 'HDD'
}} elseif ($joinedAll -match 'spindlespeed[^0-9]*[1-9][0-9]*') {{
    $diskType = 'HDD'
}}

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
    BiosUUID = $csProduct.UUID
    BiosSerial = $bios.SerialNumber
    BaseboardSerial = $baseboard.SerialNumber
    MacAddresses = @($macAddresses)
    Memory = $cs.TotalPhysicalMemory
    Processor = $cpu.Name
    Generation = $cpuGeneration
    HD = @($disks | Select-Object DeviceID, Size)
    ModHD = $diskType
    PhysicalDisks = @($physicalDisks)
    PhysicalDisksEx = @($physicalDisksEx)
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


def _infer_tag_code_from_hostname(hostname: str) -> str:
    host = (hostname or '').strip()
    if not host:
        return ''
    # Exemplos: NOTE-057, CPU-300, PRJ-0012
    match = re.search(r'^[A-Za-z]+-([0-9]{2,6})$', host, flags=re.IGNORECASE)
    if match:
        return match.group(1)
    return ''


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
    generation = _infer_cpu_generation(processor, str(payload.get('Generation') or ''))
    windows = (payload.get('Windows') or '').strip()
    memory = _parse_memory_gb(payload.get('Memory'))
    hd = _parse_total_disk(payload.get('HD') or [])
    mod_hd = _infer_mod_hd(payload, str(payload.get('ModHD') or ''))

    bios_uuid = _norm_identifier(payload.get('BiosUUID') or payload.get('UUID'))
    bios_serial = _norm_identifier(payload.get('BiosSerial') or payload.get('Serial'))
    baseboard_serial = _norm_identifier(payload.get('BaseboardSerial'))
    mac_addresses = _parse_payload_mac_addresses(payload)

    equipment = _find_equipment_by_inventory_identifiers(
        host=host,
        bios_uuid=bios_uuid,
        bios_serial=bios_serial,
        baseboard_serial=baseboard_serial,
        mac_addresses=mac_addresses,
        serial=serial,
        model=model,
        user_name=user_name,
    )
    is_new_equipment = equipment is None
    if equipment is None:
        equipment = Equipment(hostname=host)

    if is_new_equipment or not (equipment.tag_code or '').strip():
        equipment.tag_code = next_equipment_tag_code()
    equipment.needs_reconciliation = bool(source == 'agent' and is_new_equipment)
    old_hostname = equipment.hostname or ''
    equipment.user = user_name or equipment.user
    equipment.sector = sector or equipment.sector
    equipment.equipment = equipment.equipment or 'Computador'
    equipment.model = model
    equipment.brand = brand
    equipment.serial = serial
    equipment.bios_uuid = bios_uuid or equipment.bios_uuid
    equipment.bios_serial = bios_serial or equipment.bios_serial
    equipment.baseboard_serial = baseboard_serial or equipment.baseboard_serial
    equipment.mac_addresses = _merge_mac_addresses(equipment.mac_addresses, mac_addresses)
    equipment.memory = memory
    equipment.processor = processor
    equipment.generation = generation
    equipment.hd = hd
    equipment.mod_hd = mod_hd
    equipment.windows = windows
    equipment.hostname_aliases = _merge_hostname_aliases(equipment.hostname_aliases, old_hostname, host)
    equipment.hostname = host
    equipment.inventory_source = source
    equipment.last_inventory_at = now
    equipment.save()

    software_items = payload.get('Software') or []
    SoftwareInventory.objects.filter(equipment=equipment).delete()

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
