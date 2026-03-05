param(
    [Parameter(Mandatory = $false)]
    [string]$ServerUrl = 'https://erp-ti.local/api/inventory/push/',

    [Parameter(Mandatory = $false)]
    [string]$Token = '',

    [Parameter(Mandatory = $false)]
    [int]$TimeoutSec = 45,

    [Parameter(Mandatory = $false)]
    [int]$RequestId = 0
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($Token)) {
    throw 'Token nao informado. Use -Token no script/agendador.'
}

function Get-LoggedOnUserName {
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        $direct = ([string]$cs.UserName).Trim()
        if (-not [string]::IsNullOrWhiteSpace($direct)) {
            return $direct
        }
    } catch {
    }

    # Fallback: pega o dono de processo explorer.exe (usuario interativo)
    try {
        $explorers = Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue
        foreach ($proc in @($explorers)) {
            $owner = Invoke-CimMethod -InputObject $proc -MethodName GetOwner -ErrorAction SilentlyContinue
            if (-not $owner -or $owner.ReturnValue -ne 0) {
                continue
            }
            $user = ([string]$owner.User).Trim()
            $domain = ([string]$owner.Domain).Trim()
            if ([string]::IsNullOrWhiteSpace($user)) {
                continue
            }
            if ($user -match '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$') {
                continue
            }
            if ([string]::IsNullOrWhiteSpace($domain)) {
                return $user
            }
            return "$domain\$user"
        }
    } catch {
    }

    return ''
}

function Get-InstalledSoftware {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $officeLicenses = @()
    $officeSerialText = ''
    try {
        $officeLicenses = Get-CimInstance -ClassName SoftwareLicensingProduct -ErrorAction SilentlyContinue |
            Where-Object {
                $_.ApplicationID -eq '0ff1ce15-a989-479d-af46-f275c6370663' -and
                $_.PartialProductKey -and
                ([string]$_.PartialProductKey).Trim() -match '^[A-Za-z0-9]{5}$' -and
                ([string]$_.Name) -match 'Office'
            } |
            Select-Object Name, Description, LicenseStatus, PartialProductKey
    } catch {
        $officeLicenses = @()
    }

    $activeOfficeLicenses = @($officeLicenses | Where-Object { $_.LicenseStatus -eq 1 } | Sort-Object Name)
    $retailOfficeLicenses = @($activeOfficeLicenses | Where-Object { ([string]$_.Description) -match 'RETAIL' } | Sort-Object Name)

    if ($retailOfficeLicenses.Count -gt 0) {
        $officeSerialText = ([string]$retailOfficeLicenses[0].PartialProductKey).Trim().ToUpper()
    } elseif ($activeOfficeLicenses.Count -gt 0) {
        $officeSerialText = ([string]$activeOfficeLicenses[0].PartialProductKey).Trim().ToUpper()
    } elseif ($officeLicenses.Count -gt 0) {
        $officeSerialText = ([string]$officeLicenses[0].PartialProductKey).Trim().ToUpper()
    }

    function Resolve-SerialValue {
        param(
            [string]$DisplayName,
            [string]$OfficeSerial,
            [object]$Entry
        )

        $name = ([string]$DisplayName).Trim().ToLower()
        if ($name -match 'office|microsoft\s*365') {
            if (-not [string]::IsNullOrWhiteSpace($OfficeSerial)) {
                return ([string]$OfficeSerial).Trim().ToUpper()
            }
        }

        $candidates = @(
            [string]$Entry.SerialNumber,
            [string]$Entry.ProductID,
            [string]$Entry.ProductKey,
            [string]$Entry.IdentifyingNumber,
            [string]$Entry.PackageCode,
            [string]$Entry.PSChildName
        )

        foreach ($candidateRaw in $candidates) {
            $candidate = ([string]$candidateRaw).Trim()
            if ([string]::IsNullOrWhiteSpace($candidate)) {
                continue
            }

            $keyMatch = [regex]::Match($candidate, '([A-Za-z0-9]{5}(?:-[A-Za-z0-9]{5}){1,4})')
            if ($keyMatch.Success) {
                return $keyMatch.Groups[1].Value.ToUpper()
            }

            $guidBraces = [regex]::Match($candidate, '(\{[0-9A-Fa-f-]{36}\})')
            if ($guidBraces.Success) {
                return $guidBraces.Groups[1].Value.ToUpper()
            }

            $guidHex = [regex]::Match($candidate, '\b([0-9A-Fa-f]{32})\b')
            if ($guidHex.Success) {
                return $guidHex.Groups[1].Value.ToUpper()
            }

            if ($candidate -match '^[A-Za-z0-9]{5}$') {
                return $candidate.ToUpper()
            }
        }

        return ''
    }

    $items = foreach ($path in $paths) {
        try {
            Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -and $_.DisplayName.Trim().Length -gt 0 } |
                Select-Object @{
                    Name = 'Name'; Expression = { $_.DisplayName }
                }, @{
                    Name = 'Version'; Expression = { $_.DisplayVersion }
                }, @{
                    Name = 'Vendor'; Expression = { $_.Publisher }
                }, @{
                    Name = 'InstallDate'; Expression = { $_.InstallDate }
                }, @{
                    Name = 'Serial'; Expression = {
                        Resolve-SerialValue -DisplayName $_.DisplayName -OfficeSerial $officeSerialText -Entry $_
                    }
                }
        } catch {
            @()
        }
    }

    $items |
        Sort-Object Name, Version, Vendor, Serial -Unique
}

$cs = Get-CimInstance -ClassName Win32_ComputerSystem
$bios = Get-CimInstance -ClassName Win32_BIOS
$csProduct = Get-CimInstance -ClassName Win32_ComputerSystemProduct
$baseboard = Get-CimInstance -ClassName Win32_BaseBoard | Select-Object -First 1
$cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID, Size
$physicalDisks = Get-CimInstance -ClassName Win32_DiskDrive | Select-Object Model, MediaType, InterfaceType
$physicalDisksEx = @()
$macAddresses = @()
try {
    $macAddresses = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration |
        Where-Object { $_.IPEnabled -eq $true -and $_.MACAddress } |
        Select-Object -ExpandProperty MACAddress
} catch {
    $macAddresses = @()
}
if (Get-Command Get-PhysicalDisk -ErrorAction SilentlyContinue) {
    try {
        $physicalDisksEx = Get-PhysicalDisk | Select-Object FriendlyName, MediaType, BusType, SpindleSpeed
    } catch {
        $physicalDisksEx = @()
    }
}

$cpuGeneration = ''
if ($cpu.Name -match 'Core\s*(\(\s*TM\s*\)\s*)?Ultra\s*[3579]?\s*([0-9]{3,5})') {
    $digits = $Matches[2]
    if ($digits.Length -ge 5) {
        $cpuGeneration = "{0}a" -f $digits.Substring(0,2)
    } elseif ($digits.Length -ge 3) {
        $cpuGeneration = "{0}a" -f $digits.Substring(0,1)
    }
} elseif ($cpu.Name -match 'i[3579]-([0-9]{4,5})') {
    $digits = $Matches[1]
    if ($digits.Length -ge 5) {
        $cpuGeneration = "{0}a" -f $digits.Substring(0,2)
    } else {
        $cpuGeneration = "{0}a" -f $digits.Substring(0,1)
    }
} elseif ($cpu.Name -match 'i[3579](\s*-\s*|\s+cpu\s+|\s+)([A-Za-z]{0,2}\s*)?([0-9]{3,5})[A-Za-z]{0,2}\b') {
    $digits = $Matches[3]
    if ($digits.Length -eq 3) {
        $cpuGeneration = '1a'
    } elseif ($digits.Length -ge 5) {
        $cpuGeneration = "{0}a" -f $digits.Substring(0,2)
    } else {
        $cpuGeneration = "{0}a" -f $digits.Substring(0,1)
    }
} elseif ($cpu.Name -match 'Ryzen\s+\d\s+([0-9]{4,5})') {
    $digits = $Matches[1]
    $cpuGeneration = "{0}a" -f $digits.Substring(0,1)
} elseif ($cpu.Name -match 'core\s*(\(\s*tm\s*\)\s*)?2\b') {
    $cpuGeneration = 'Legado (Core 2)'
} elseif ($cpu.Name -match '\b(Pentium|Celeron|Xeon)\b') {
    $cpuGeneration = 'Legado'
}

$diskType = 'Nao identificado'
$joinedDisks = (@($physicalDisks | ForEach-Object { ($_.Model + ' ' + $_.MediaType + ' ' + $_.InterfaceType) }) -join ' ').ToLower()
$joinedDisksEx = (@($physicalDisksEx | ForEach-Object { ($_.FriendlyName + ' ' + $_.MediaType + ' ' + $_.BusType + ' ' + $_.SpindleSpeed) }) -join ' ').ToLower()
$joinedAll = ($joinedDisks + ' ' + $joinedDisksEx).Trim()
if ($joinedAll -match 'nvme') {
    $diskType = 'SSD NVMe (M.2)'
} elseif ($joinedAll -match 'ssd|solid state') {
    $diskType = 'SSD'
} elseif ($joinedAll -match 'hdd') {
    $diskType = 'HDD'
} elseif ($joinedAll -match 'spindlespeed[^0-9]*[1-9][0-9]*') {
    $diskType = 'HDD'
}

$fwDomainEnabled = $null
$fwPrivateEnabled = $null
$fwPublicEnabled = $null
try {
    $fwProfiles = Get-NetFirewallProfile -ErrorAction Stop
    foreach ($profile in $fwProfiles) {
        $name = ([string]$profile.Name).Trim()
        $enabled = [bool]$profile.Enabled
        if ($name -eq 'Domain') {
            $fwDomainEnabled = $enabled
        } elseif ($name -eq 'Private') {
            $fwPrivateEnabled = $enabled
        } elseif ($name -eq 'Public') {
            $fwPublicEnabled = $enabled
        }
    }
} catch {
}

$defenderServiceRunning = $null
try {
    $defSvc = Get-Service -Name WinDefend -ErrorAction Stop
    $defenderServiceRunning = ($defSvc.Status -eq 'Running')
} catch {
}

$defenderRealtimeEnabled = $null
try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    $defenderRealtimeEnabled = [bool]$mp.RealTimeProtectionEnabled
} catch {
}

$antivirusNames = @()
try {
    $antivirusNames = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction Stop |
        Where-Object { $_.displayName } |
        Select-Object -ExpandProperty displayName
} catch {
    $antivirusNames = @()
}
if ((-not $antivirusNames -or $antivirusNames.Count -eq 0) -and ($defenderServiceRunning -eq $true)) {
    $antivirusNames = @('Microsoft Defender Antivirus')
}
$antivirusNames = @($antivirusNames | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ } | Select-Object -Unique)
$fwAnyDisabled = $false
if ($fwDomainEnabled -eq $false -or $fwPrivateEnabled -eq $false -or $fwPublicEnabled -eq $false) {
    $fwAnyDisabled = $true
}

$loggedOnUser = Get-LoggedOnUserName

$payload = [PSCustomObject]@{
    Hostname  = $env:COMPUTERNAME
    UserName  = $loggedOnUser
    Sector    = ''
    Model     = $cs.Model
    Brand     = $cs.Manufacturer
    Serial    = $bios.SerialNumber
    BiosUUID  = $csProduct.UUID
    BiosSerial = $bios.SerialNumber
    BaseboardSerial = $baseboard.SerialNumber
    MacAddresses = @($macAddresses)
    Memory    = $cs.TotalPhysicalMemory
    Processor = $cpu.Name
    Generation = $cpuGeneration
    HD        = @($disks)
    ModHD     = $diskType
    PhysicalDisks = @($physicalDisks)
    PhysicalDisksEx = @($physicalDisksEx)
    Windows   = $os.Caption
    FirewallDomainEnabled = $fwDomainEnabled
    FirewallPrivateEnabled = $fwPrivateEnabled
    FirewallPublicEnabled = $fwPublicEnabled
    FirewallAnyDisabled = $fwAnyDisabled
    DefenderServiceRunning = $defenderServiceRunning
    DefenderRealtimeEnabled = $defenderRealtimeEnabled
    AntivirusNames = @($antivirusNames)
    Software  = @(Get-InstalledSoftware)
    RequestId = if ($RequestId -gt 0) { $RequestId } else { $null }
}

$json = $payload | ConvertTo-Json -Depth 8

$headers = @{
    Authorization = "Bearer $Token"
}

$response = Invoke-RestMethod `
    -Method Post `
    -Uri $ServerUrl `
    -Headers $headers `
    -ContentType 'application/json; charset=utf-8' `
    -Body $json `
    -TimeoutSec $TimeoutSec

Write-Output ("Inventario enviado com sucesso. Updated=" + $response.updated + " Failed=" + $response.failed)
