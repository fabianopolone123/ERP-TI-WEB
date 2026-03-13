param(
    [Parameter(Mandatory = $false)]
    [string]$AppUrl = "https://erp-ti.local",

    [Parameter(Mandatory = $false)]
    [string]$AppName = "ERP TI",

    [Parameter(Mandatory = $false)]
    [ValidateSet("Auto", "Edge", "Chrome")]
    [string]$Browser = "Auto",

    [Parameter(Mandatory = $false)]
    [string]$ProfileDir = "$env:LOCALAPPDATA\ERP-TI-Desktop",

    [Parameter(Mandatory = $false)]
    [switch]$InstallStartup,

    [Parameter(Mandatory = $false)]
    [switch]$AllowInsecureTls
)

$ErrorActionPreference = "Stop"

function Resolve-BrowserPath {
    param(
        [string]$Choice
    )

    $edgeCandidates = @(
        "$env:ProgramFiles(x86)\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
    )
    $chromeCandidates = @(
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "$env:ProgramFiles(x86)\Google\Chrome\Application\chrome.exe"
    )

    $resolveFirst = {
        param([string[]]$Candidates)
        foreach ($item in $Candidates) {
            if (Test-Path $item) {
                return $item
            }
        }
        return $null
    }

    if ($Choice -eq "Edge") {
        $edge = & $resolveFirst $edgeCandidates
        if ($edge) { return $edge }
        throw "Microsoft Edge nao encontrado."
    }

    if ($Choice -eq "Chrome") {
        $chrome = & $resolveFirst $chromeCandidates
        if ($chrome) { return $chrome }
        throw "Google Chrome nao encontrado."
    }

    $autoEdge = & $resolveFirst $edgeCandidates
    if ($autoEdge) { return $autoEdge }
    $autoChrome = & $resolveFirst $chromeCandidates
    if ($autoChrome) { return $autoChrome }
    throw "Nenhum navegador suportado encontrado (Edge/Chrome)."
}

function New-AppShortcut {
    param(
        [string]$ShortcutPath,
        [string]$TargetPath,
        [string]$Arguments,
        [string]$WorkingDirectory,
        [string]$IconLocation
    )

    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($ShortcutPath)
    $shortcut.TargetPath = $TargetPath
    $shortcut.Arguments = $Arguments
    $shortcut.WorkingDirectory = $WorkingDirectory
    $shortcut.IconLocation = $IconLocation
    $shortcut.Save()
}

$browserPath = Resolve-BrowserPath -Choice $Browser
if (-not (Test-Path $ProfileDir)) {
    New-Item -Path $ProfileDir -ItemType Directory -Force | Out-Null
}

$appArgs = @(
    "--app=$AppUrl",
    "--user-data-dir=""$ProfileDir""",
    "--window-size=1400,900"
)
if ($AllowInsecureTls) {
    $appArgs += "--ignore-certificate-errors"
}
$arguments = ($appArgs -join " ")

$desktopPath = [Environment]::GetFolderPath("Desktop")
$startMenuPath = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
$startupPath = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup"

$desktopShortcut = Join-Path $desktopPath "$AppName.lnk"
$startShortcut = Join-Path $startMenuPath "$AppName.lnk"

New-AppShortcut `
    -ShortcutPath $desktopShortcut `
    -TargetPath $browserPath `
    -Arguments $arguments `
    -WorkingDirectory (Split-Path -Parent $browserPath) `
    -IconLocation "$browserPath,0"

New-AppShortcut `
    -ShortcutPath $startShortcut `
    -TargetPath $browserPath `
    -Arguments $arguments `
    -WorkingDirectory (Split-Path -Parent $browserPath) `
    -IconLocation "$browserPath,0"

if ($InstallStartup) {
    $startupShortcut = Join-Path $startupPath "$AppName.lnk"
    New-AppShortcut `
        -ShortcutPath $startupShortcut `
        -TargetPath $browserPath `
        -Arguments $arguments `
        -WorkingDirectory (Split-Path -Parent $browserPath) `
        -IconLocation "$browserPath,0"
    Write-Host "[INFO] Inicializacao automatica habilitada: $startupShortcut"
}

Write-Host "[OK] App desktop instalado para o usuario atual."
Write-Host "[INFO] Navegador: $browserPath"
Write-Host "[INFO] URL: $AppUrl"
Write-Host "[INFO] Atalho Desktop: $desktopShortcut"
Write-Host "[INFO] Atalho Menu Iniciar: $startShortcut"
