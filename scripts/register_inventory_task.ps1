param(
    [Parameter(Mandatory = $false)]
    [string]$TaskName = 'ERP TI Inventory Agent',

    [Parameter(Mandatory = $false)]
    [string]$ScriptPath = 'C:\ProgramData\ERP-TI\inventory_agent.ps1',

    [Parameter(Mandatory = $false)]
    [string]$ServerUrl = 'http://ti-fabiano:8000/api/inventory/push/',

    [Parameter(Mandatory = $true)]
    [string]$Token
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -Path $ScriptPath)) {
    throw "Script nao encontrado: $ScriptPath"
}

$psArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -ServerUrl `"$ServerUrl`" -Token `"$Token`""
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $psArgs

$triggerBoot = New-ScheduledTaskTrigger -AtStartup
$triggerDaily = New-ScheduledTaskTrigger -Daily -At 08:00

$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RunOnlyIfNetworkAvailable -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 30)

Register-ScheduledTask \
    -TaskName $TaskName \
    -Action $action \
    -Trigger @($triggerBoot, $triggerDaily) \
    -Principal $principal \
    -Settings $settings \
    -Force | Out-Null

Write-Output "Tarefa '$TaskName' registrada com sucesso."
