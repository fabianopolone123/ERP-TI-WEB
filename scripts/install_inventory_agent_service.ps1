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
    [bool]$EnableLogonPush = $true
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
$sourceDaemon = Join-Path $scriptRoot 'inventory_agent_daemon.ps1'
if (-not (Test-Path $sourceAgent)) {
    throw "Arquivo nao encontrado: $sourceAgent"
}
if (-not (Test-Path $sourceDaemon)) {
    throw "Arquivo nao encontrado: $sourceDaemon"
}

New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $TargetDir 'logs') -Force | Out-Null

$targetAgent = Join-Path $TargetDir 'inventory_agent.ps1'
$targetDaemon = Join-Path $TargetDir 'inventory_agent_daemon.ps1'
$logPath = Join-Path $TargetDir 'logs\inventory_agent_daemon.log'
$taskNameLogonPush = "$TaskName - Logon Push"
$serverBaseNormalized = ([string]$ServerBaseUrl).Trim().TrimEnd('/')
if ([string]::IsNullOrWhiteSpace($serverBaseNormalized)) {
    throw 'ServerBaseUrl nao informado.'
}
$pushUrl = "$serverBaseNormalized/api/inventory/push/"

Copy-Item -Path $sourceAgent -Destination $targetAgent -Force
Copy-Item -Path $sourceDaemon -Destination $targetDaemon -Force

$legacy = Get-Service -Name $LegacyServiceName -ErrorAction SilentlyContinue
if ($legacy) {
    try { Stop-Service -Name $LegacyServiceName -Force -ErrorAction SilentlyContinue } catch {}
    & sc.exe delete $LegacyServiceName | Out-Null
}

$args = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$targetDaemon`" -ServerBaseUrl `"$serverBaseNormalized`" -Token `"$Token`" -AgentScriptPath `"$targetAgent`" -PollIntervalSec $PollIntervalSec -LogPath `"$logPath`""
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $args
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable `
    -DontStopIfGoingOnBatteries `
    -AllowStartIfOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Hours 0) `
    -RestartCount 5 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -MultipleInstances IgnoreNew

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Force | Out-Null

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

try {
    Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
} catch {
    # Pode falhar se a tarefa já estiver executando.
}

Write-Output "Tarefa '$TaskName' configurada e iniciada com sucesso."
