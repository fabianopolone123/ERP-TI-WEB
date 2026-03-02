param(
    [Parameter(Mandatory = $false)]
    [string]$InstallerPath = '',

    [Parameter(Mandatory = $false)]
    [string]$WingetId = 'GlavSoft.TightVNC',

    [Parameter(Mandatory = $false)]
    [string]$ServiceName = 'tvnserver',

    [Parameter(Mandatory = $false)]
    [int]$Port = 5900,

    [Parameter(Mandatory = $false)]
    [string]$AllowedRemote = 'LocalSubnet',

    [Parameter(Mandatory = $false)]
    [switch]$SkipInstall,

    [Parameter(Mandatory = $false)]
    [switch]$SkipFirewall
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Test-IsAdmin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-TvnServerPath {
    $candidates = @(
        "$env:ProgramFiles\TightVNC\tvnserver.exe",
        "$env:ProgramFiles(x86)\TightVNC\tvnserver.exe"
    )
    foreach ($path in $candidates) {
        if (Test-Path $path) {
            return $path
        }
    }
    return ''
}

function Install-TightVnc {
    if ($SkipInstall) {
        return
    }

    if (Resolve-TvnServerPath) {
        return
    }

    if (-not [string]::IsNullOrWhiteSpace($InstallerPath)) {
        if (-not (Test-Path $InstallerPath)) {
            throw "Instalador nao encontrado: $InstallerPath"
        }

        $fullPath = (Resolve-Path $InstallerPath).Path
        $extension = [IO.Path]::GetExtension($fullPath).ToLowerInvariant()
        if ($extension -eq '.msi') {
            $arguments = @('/i', "`"$fullPath`"", '/qn', '/norestart')
            $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList $arguments -Wait -PassThru
            if ($proc.ExitCode -ne 0) {
                throw "Falha ao instalar MSI do TightVNC. ExitCode=$($proc.ExitCode)"
            }
            return
        }

        $silentArgs = '/verysilent /norestart'
        $proc = Start-Process -FilePath $fullPath -ArgumentList $silentArgs -Wait -PassThru
        if ($proc.ExitCode -ne 0) {
            throw "Falha ao instalar EXE do TightVNC. ExitCode=$($proc.ExitCode)"
        }
        return
    }

    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $winget) {
        throw 'TightVNC nao encontrado e winget indisponivel. Informe -InstallerPath para instalacao offline.'
    }

    $wingetArgs = @(
        'install',
        '--id', $WingetId,
        '--exact',
        '--silent',
        '--accept-package-agreements',
        '--accept-source-agreements',
        '--source', 'winget'
    )
    $proc = Start-Process -FilePath $winget.Source -ArgumentList $wingetArgs -Wait -PassThru -NoNewWindow
    if ($proc.ExitCode -ne 0) {
        throw "Falha ao instalar via winget ($WingetId). ExitCode=$($proc.ExitCode)"
    }
}

function Ensure-VncService {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TvnServerExe
    )

    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service) {
        try {
            & $TvnServerExe -install | Out-Null
        } catch {
            # segue para revalidar no SCM
        }
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    }

    if (-not $service) {
        throw "Servico VNC '$ServiceName' nao encontrado apos tentativa de instalacao."
    }

    Set-Service -Name $ServiceName -StartupType Automatic
    if ($service.Status -ne 'Running') {
        Start-Service -Name $ServiceName
    }
}

function Ensure-FirewallRule {
    if ($SkipFirewall) {
        return
    }

    $ruleName = "ERP-TI VNC TCP $Port"
    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($existing) {
        Remove-NetFirewallRule -DisplayName $ruleName | Out-Null
    }

    New-NetFirewallRule `
        -DisplayName $ruleName `
        -Direction Inbound `
        -Action Allow `
        -Profile Domain `
        -Protocol TCP `
        -LocalPort $Port `
        -RemoteAddress $AllowedRemote | Out-Null
}

if (-not (Test-IsAdmin)) {
    throw 'Execute este script como Administrador (necessario para instalar servico e firewall).'
}

Install-TightVnc
$tvnServerExe = Resolve-TvnServerPath
if (-not $tvnServerExe) {
    throw 'Nao foi possivel localizar tvnserver.exe apos a instalacao.'
}

Ensure-VncService -TvnServerExe $tvnServerExe
Ensure-FirewallRule

Write-Output "VNC agente configurado com sucesso. Servico=$ServiceName Porta=$Port Remotos=$AllowedRemote"
