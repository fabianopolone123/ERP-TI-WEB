param(
    [Parameter(Mandatory = $false)]
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = Get-Date -Format "yyyy.MM.dd-HHmmss"
}

$root = Split-Path -Parent $PSScriptRoot
$markerPath = Join-Path $root ".release-version"

Set-Content -Path $markerPath -Value $Version -Encoding UTF8

Write-Host "[OK] Versao publicada: $Version"
Write-Host "[INFO] Arquivo atualizado: $markerPath"
