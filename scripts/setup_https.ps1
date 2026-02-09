param(
    [Parameter(Mandatory = $false)]
    [string]$HostName = "erp-ti.local",

    [Parameter(Mandatory = $false)]
    [string]$ServerIP = "127.0.0.1"
)

$ErrorActionPreference = "Stop"

function Ensure-Caddy {
    if (Get-Command caddy -ErrorAction SilentlyContinue) {
        return
    }

    Write-Host "[INFO] Caddy nao encontrado. Tentando instalar via winget..."
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        throw "winget nao encontrado. Instale o Caddy manualmente: https://caddyserver.com/download"
    }

    winget install --id CaddyServer.Caddy --exact --accept-package-agreements --accept-source-agreements
    if (-not (Get-Command caddy -ErrorAction SilentlyContinue)) {
        throw "Caddy nao foi instalado corretamente."
    }
}

function Update-HostsFile {
    param(
        [string]$Ip,
        [string]$Name
    )

    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    $raw = Get-Content $hostsPath -ErrorAction SilentlyContinue
    $pattern = "^\s*" + [regex]::Escape($Ip) + "\s+" + [regex]::Escape($Name) + "(\s|$)"
    $exists = $false
    foreach ($line in $raw) {
        if ($line -match $pattern) {
            $exists = $true
            break
        }
    }

    if (-not $exists) {
        Add-Content -Path $hostsPath -Value "$Ip`t$Name"
        Write-Host "[INFO] hosts atualizado: $Ip $Name"
    }
    else {
        Write-Host "[INFO] hosts ja possui: $Ip $Name"
    }
}

function Write-Caddyfile {
    param(
        [string]$Name
    )

    $root = Split-Path -Parent $PSScriptRoot
    $caddyfilePath = Join-Path $root "Caddyfile"
    $content = @"
{
    auto_https disable_redirects
}

$Name {
    tls internal
    reverse_proxy 127.0.0.1:8000
}
"@
    Set-Content -Path $caddyfilePath -Value $content -Encoding UTF8
    Write-Host "[INFO] Caddyfile gerado em $caddyfilePath"
}

function Ensure-EnvHost {
    param(
        [string]$Name
    )

    $root = Split-Path -Parent $PSScriptRoot
    $envPath = Join-Path $root ".env"
    if (-not (Test-Path $envPath)) {
        throw ".env nao encontrado em $root"
    }

    $lines = Get-Content $envPath -ErrorAction Stop
    $key = "EXTRA_ALLOWED_HOSTS"
    $updated = $false

    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match "^\s*$key\s*=") {
            $value = ($lines[$i] -split "=", 2)[1].Trim()
            $items = @()
            if ($value) {
                $items = $value.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            }
            if ($items -notcontains $Name) {
                $items += $Name
            }
            $lines[$i] = "$key=" + ($items -join ",")
            $updated = $true
            break
        }
    }

    if (-not $updated) {
        $lines += "$key=$Name"
    }

    Set-Content -Path $envPath -Value $lines -Encoding UTF8
    Write-Host "[INFO] .env atualizado com EXTRA_ALLOWED_HOSTS."
}

Ensure-Caddy
Update-HostsFile -Ip $ServerIP -Name $HostName
Write-Caddyfile -Name $HostName
Ensure-EnvHost -Name $HostName

Write-Host ""
Write-Host "[OK] Setup HTTPS concluido."
Write-Host "Hostname: https://$HostName"
Write-Host "Proximo passo: execute start_erp_https.bat"
Write-Host ""
Write-Host "Para os OUTROS PCs:"
Write-Host "1) Adicionar no hosts: $ServerIP $HostName"
Write-Host "2) Instalar o certificado raiz do Caddy em 'Trusted Root Certification Authorities'."
Write-Host "   Caminho padrao do certificado no servidor:"
Write-Host "   $env:APPDATA\\Caddy\\pki\\authorities\\local\\root.crt"
