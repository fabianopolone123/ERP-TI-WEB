param(
    [Parameter(Mandatory = $false)]
    [string]$TargetDir = 'C:\ProgramData\ERP-TI',

    [Parameter(Mandatory = $false)]
    [string]$TaskName = 'ERP TI Inventory Agent',

    [Parameter(Mandatory = $false)]
    [string]$LegacyServiceName = 'ErpTiInventoryAgent',

    [Parameter(Mandatory = $false)]
    [string]$ServerBaseUrl = 'https://erp-ti.local',

    [Parameter(Mandatory = $true)]
    [string]$Token,

    [Parameter(Mandatory = $false)]
    [int]$PollIntervalSec = 45,

    [Parameter(Mandatory = $false)]
    [bool]$EnableLogonPush = $false,

    [Parameter(Mandatory = $false)]
    [bool]$EnableStartupPush = $true
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    throw 'Execute como Administrador.'
}

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$sourceAgent = Join-Path $scriptRoot 'inventory_agent.ps1'
if (-not (Test-Path $sourceAgent)) {
    throw "Arquivo nao encontrado: $sourceAgent"
}

New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $TargetDir 'logs') -Force | Out-Null

$targetAgent = Join-Path $TargetDir 'inventory_agent.ps1'
$taskNameLogonPush = "$TaskName - Logon Push"
$taskNameStartupPush = "$TaskName - Startup Push"
$serverBaseNormalized = ([string]$ServerBaseUrl).Trim().TrimEnd('/')
if ([string]::IsNullOrWhiteSpace($serverBaseNormalized)) {
    throw 'ServerBaseUrl nao informado.'
}
$pushUrl = "$serverBaseNormalized/api/inventory/push/"

Copy-Item -Path $sourceAgent -Destination $targetAgent -Force

$legacy = Get-Service -Name $LegacyServiceName -ErrorAction SilentlyContinue
if ($legacy) {
    try { Stop-Service -Name $LegacyServiceName -Force -ErrorAction SilentlyContinue } catch {}
    & sc.exe delete $LegacyServiceName | Out-Null
}

# Remove tarefa antiga do daemon, caso exista.
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest

if ($EnableLogonPush) {
    $logonArgs = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$targetAgent`" -ServerUrl `"$pushUrl`" -Token `"$Token`" -TimeoutSec 60"
    $logonAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $logonArgs
    $logonTrigger = New-ScheduledTaskTrigger -AtLogOn
    $logonSettings = New-ScheduledTaskSettingsSet `
        -StartWhenAvailable `
        -RunOnlyIfNetworkAvailable `
        -DontStopIfGoingOnBatteries `
        -AllowStartIfOnBatteries `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 15) `
        -MultipleInstances IgnoreNew

    Register-ScheduledTask `
        -TaskName $taskNameLogonPush `
        -Action $logonAction `
        -Trigger $logonTrigger `
        -Principal $principal `
        -Settings $logonSettings `
        -Force | Out-Null
} else {
    Unregister-ScheduledTask -TaskName $taskNameLogonPush -Confirm:$false -ErrorAction SilentlyContinue
}

if ($EnableStartupPush) {
    $startupPushArgs = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$targetAgent`" -ServerUrl `"$pushUrl`" -Token `"$Token`" -TimeoutSec 60"
    $startupPushAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $startupPushArgs
    $startupPushTrigger = New-ScheduledTaskTrigger -AtStartup
    $startupPushSettings = New-ScheduledTaskSettingsSet `
        -StartWhenAvailable `
        -RunOnlyIfNetworkAvailable `
        -DontStopIfGoingOnBatteries `
        -AllowStartIfOnBatteries `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 15) `
        -MultipleInstances IgnoreNew

    Register-ScheduledTask `
        -TaskName $taskNameStartupPush `
        -Action $startupPushAction `
        -Trigger $startupPushTrigger `
        -Principal $principal `
        -Settings $startupPushSettings `
        -Force | Out-Null
} else {
    Unregister-ScheduledTask -TaskName $taskNameStartupPush -Confirm:$false -ErrorAction SilentlyContinue
}

if ($EnableStartupPush) {
    try {
        Start-ScheduledTask -TaskName $taskNameStartupPush -ErrorAction Stop
    } catch {
        # Ignorar falha no disparo imediato; no proximo boot a tarefa roda automaticamente.
    }
}

Write-Output "Tarefas de inventario (startup/logon) configuradas e iniciadas com sucesso."

