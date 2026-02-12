param(
    [Parameter(Mandatory = $false)]
    [string]$ServerUrl = 'http://ti-fabiano:8000/api/inventory/push/',

    [Parameter(Mandatory = $false)]
    [string]$Token = '',

    [Parameter(Mandatory = $false)]
    [int]$TimeoutSec = 45
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($Token)) {
    throw 'Token nao informado. Use -Token no script/agendador.'
}

function Get-InstalledSoftware {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

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
                }
        } catch {
            @()
        }
    }

    $items |
        Sort-Object Name -Unique
}

$cs = Get-CimInstance -ClassName Win32_ComputerSystem
$bios = Get-CimInstance -ClassName Win32_BIOS
$cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID, Size
$physicalDisks = Get-CimInstance -ClassName Win32_DiskDrive | Select-Object Model, MediaType, InterfaceType

$cpuGeneration = ''
if ($cpu.Name -match 'i[3579]-([0-9]{4,5})') {
    $digits = $Matches[1]
    if ($digits.Length -ge 5) {
        $cpuGeneration = "{0}a" -f $digits.Substring(0,2)
    } else {
        $cpuGeneration = "{0}a" -f $digits.Substring(0,1)
    }
} elseif ($cpu.Name -match 'Ryzen\s+\d\s+([0-9]{4,5})') {
    $digits = $Matches[1]
    $cpuGeneration = "{0}a" -f $digits.Substring(0,1)
}

$diskType = ''
$joinedDisks = (@($physicalDisks | ForEach-Object { ($_.Model + ' ' + $_.MediaType + ' ' + $_.InterfaceType) }) -join ' ').ToLower()
if ($joinedDisks -match 'nvme|ssd|solid state') {
    $diskType = 'SSD'
} elseif ($joinedDisks -match 'hdd') {
    $diskType = 'HDD'
} elseif ($joinedDisks -match 'sata|scsi') {
    $diskType = 'HDD'
}

$payload = [PSCustomObject]@{
    Hostname  = $env:COMPUTERNAME
    UserName  = $cs.UserName
    Sector    = ''
    Model     = $cs.Model
    Brand     = $cs.Manufacturer
    Serial    = $bios.SerialNumber
    Memory    = $cs.TotalPhysicalMemory
    Processor = $cpu.Name
    Generation = $cpuGeneration
    HD        = @($disks)
    ModHD     = $diskType
    PhysicalDisks = @($physicalDisks)
    Windows   = $os.Caption
    Software  = @(Get-InstalledSoftware)
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
