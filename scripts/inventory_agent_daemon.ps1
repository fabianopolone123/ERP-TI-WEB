param(
    [Parameter(Mandatory = $false)]
    [string]$ServerBaseUrl = 'https://erp-ti.local',

    [Parameter(Mandatory = $false)]
    [string]$Token = '',

    [Parameter(Mandatory = $false)]
    [string]$AgentScriptPath = 'C:\ProgramData\ERP-TI\inventory_agent.ps1',

    [Parameter(Mandatory = $false)]
    [int]$PollIntervalSec = 45,

    [Parameter(Mandatory = $false)]
    [int]$TimeoutSec = 30,

    [Parameter(Mandatory = $false)]
    [string]$LogPath = 'C:\ProgramData\ERP-TI\logs\inventory_agent_daemon.log'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($Token)) {
    throw 'Token nao informado para o daemon de inventario.'
}
if (-not (Test-Path -Path $AgentScriptPath)) {
    throw "Script de inventario nao encontrado: $AgentScriptPath"
}

$base = ([string]$ServerBaseUrl).Trim().TrimEnd('/')
if ([string]::IsNullOrWhiteSpace($base)) {
    throw 'ServerBaseUrl nao informado.'
}

$computerHost = ([string]$env:COMPUTERNAME).Trim()
if ([string]::IsNullOrWhiteSpace($computerHost)) {
    throw 'Nao foi possivel identificar COMPUTERNAME.'
}

$nextUrl = "$base/api/inventory/pull-next/?host=$([System.Uri]::EscapeDataString($computerHost))"
$ackUrl = "$base/api/inventory/pull-ack/"
$pushUrl = "$base/api/inventory/push/"

$logDir = Split-Path -Parent $LogPath
if (-not [string]::IsNullOrWhiteSpace($logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

function Write-Log {
    param([string]$Message)
    $line = ('{0} | {1}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Message)
    Add-Content -Path $LogPath -Value $line
}

function Send-Ack {
    param(
        [int]$RequestId,
        [string]$Status,
        [string]$Message
    )
    try {
        $headers = @{ Authorization = "Bearer $Token" }
        $body = @{
            request_id = $RequestId
            status = $Status
            message = $Message
            host = $computerHost
        } | ConvertTo-Json -Depth 4
        Invoke-RestMethod `
            -Method Post `
            -Uri $ackUrl `
            -Headers $headers `
            -ContentType 'application/json; charset=utf-8' `
            -Body $body `
            -TimeoutSec $TimeoutSec | Out-Null
    } catch {
        Write-Log ("Falha ao enviar ACK request_id={0}: {1}" -f $RequestId, $_.Exception.Message)
    }
}

Write-Log ("Daemon iniciado. Host={0} Poll={1}s" -f $computerHost, $PollIntervalSec)

while ($true) {
    try {
        $headers = @{ Authorization = "Bearer $Token" }
        $next = Invoke-RestMethod -Method Get -Uri $nextUrl -Headers $headers -TimeoutSec $TimeoutSec

        if ($next -and $next.ok -and $next.request) {
            $requestId = [int]$next.request.id
            $targetHost = ([string]$next.request.hostname).Trim()
            if ([string]::IsNullOrWhiteSpace($targetHost)) {
                Send-Ack -RequestId $requestId -Status 'failed' -Message 'Solicitacao sem hostname.'
                Start-Sleep -Seconds ([Math]::Max(5, [int]$PollIntervalSec))
                continue
            }

            if ($targetHost.ToUpperInvariant() -ne $computerHost.ToUpperInvariant()) {
                Send-Ack -RequestId $requestId -Status 'failed' -Message ("Hostname divergente. Agente={0} Solicitacao={1}" -f $computerHost, $targetHost)
                Start-Sleep -Seconds ([Math]::Max(5, [int]$PollIntervalSec))
                continue
            }

            Write-Log ("Solicitacao recebida request_id={0}. Iniciando coleta." -f $requestId)
            $args = @(
                '-NoProfile',
                '-ExecutionPolicy',
                'Bypass',
                '-File',
                $AgentScriptPath,
                '-ServerUrl',
                $pushUrl,
                '-Token',
                $Token,
                '-TimeoutSec',
                [string][Math]::Max(15, $TimeoutSec),
                '-RequestId',
                [string]$requestId
            )
            $proc = Start-Process -FilePath 'powershell.exe' -ArgumentList $args -PassThru -Wait -WindowStyle Hidden
            if ($proc.ExitCode -ne 0) {
                Send-Ack -RequestId $requestId -Status 'failed' -Message ("Coleta falhou com ExitCode={0}" -f $proc.ExitCode)
                Write-Log ("Falha na coleta request_id={0} exit={1}" -f $requestId, $proc.ExitCode)
            } else {
                Write-Log ("Coleta enviada request_id={0}" -f $requestId)
            }
        }
    } catch {
        Write-Log ("Loop erro: {0}" -f $_.Exception.Message)
    }

    Start-Sleep -Seconds ([Math]::Max(5, [int]$PollIntervalSec))
}
