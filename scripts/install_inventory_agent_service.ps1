param(
    [Parameter(Mandatory = $false)]
    [string]$TargetDir = 'C:\ProgramData\ERP-TI',

    [Parameter(Mandatory = $false)]
    [string]$ServiceName = 'ErpTiInventoryAgent',

    [Parameter(Mandatory = $false)]
    [string]$DisplayName = 'ERP TI Inventory Agent Service',

    [Parameter(Mandatory = $false)]
    [string]$ServerBaseUrl = 'https://erp-ti.local',

    [Parameter(Mandatory = $true)]
    [string]$Token,

    [Parameter(Mandatory = $false)]
    [int]$PollIntervalSec = 45
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

Copy-Item -Path $sourceAgent -Destination $targetAgent -Force
Copy-Item -Path $sourceDaemon -Destination $targetDaemon -Force

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
$binPath = "`"powershell.exe`" -NoProfile -ExecutionPolicy Bypass -File `"$targetDaemon`" -ServerBaseUrl `"$ServerBaseUrl`" -Token `"$Token`" -AgentScriptPath `"$targetAgent`" -PollIntervalSec $PollIntervalSec -LogPath `"$logPath`""

if ($existing) {
    & sc.exe config $ServiceName binPath= "$binPath" start= auto DisplayName= "$DisplayName" | Out-Null
} else {
    & sc.exe create $ServiceName binPath= "$binPath" start= auto DisplayName= "$DisplayName" obj= "LocalSystem" | Out-Null
}

Start-Service -Name $ServiceName
Write-Output "Servico '$ServiceName' configurado e iniciado com sucesso."
