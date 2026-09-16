param(
    [switch]$SkipBuildTests
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Open PowerShell as Administrator and run .\bootstrap.ps1 again.'
    }
}

function Refresh-Path {
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $user = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = "$machine;$user"
}

function Ensure-Winget {
    if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
        throw 'winget is required for automatic prerequisite installation. Install Microsoft App Installer, then rerun bootstrap.ps1.'
    }
}

function Ensure-Python {
    if (Get-Command py.exe -ErrorAction SilentlyContinue) {
        try {
            & py.exe -3.12 -c "import sys; assert sys.version_info[:2] == (3, 12)" 2>$null
            if ($LASTEXITCODE -eq 0) { return }
        } catch {}
    }
    Write-Host '[MON] Installing Python 3.12...'
    Ensure-Winget
    winget install --id Python.Python.3.12 -e --silent --accept-package-agreements --accept-source-agreements
    Refresh-Path
    if (-not (Get-Command py.exe -ErrorAction SilentlyContinue)) {
        throw 'Python 3.12 installation completed but py.exe is not available in PATH. Sign out/in once and rerun bootstrap.ps1.'
    }
}

function Find-TShark {
    $command = Get-Command tshark.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $candidate = 'C:\Program Files\Wireshark\tshark.exe'
    if (Test-Path $candidate) { return $candidate }
    return $null
}

function Ensure-WiresharkNpcap {
    $tshark = Find-TShark
    if (-not $tshark) {
        Write-Host '[MON] Installing Wireshark/TShark...'
        Ensure-Winget
        winget install --id WiresharkFoundation.Wireshark -e --silent --accept-package-agreements --accept-source-agreements
        Refresh-Path
        $tshark = Find-TShark
    }
    if (-not $tshark) {
        throw 'TShark was not found after Wireshark installation.'
    }
    $interfaces = & $tshark -D 2>&1
    if ($LASTEXITCODE -ne 0 -or -not $interfaces) {
        throw 'TShark cannot enumerate capture adapters. Repair/reinstall Npcap, then rerun bootstrap.ps1.'
    }
    Write-Host "[MON] TShark: $tshark"
    Write-Host '[MON] Npcap capture adapters detected.'
}

function Write-DeploymentManifest {
    $dir = Join-Path $env:ProgramData 'MON'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $commit = (git rev-parse HEAD 2>$null)
    $branch = (git branch --show-current 2>$null)
    $manifest = [ordered]@{
        installed = $true
        profile = 'windows-native-single-source'
        version = '1.0.0-windows'
        branch = $branch
        commit = $commit
        installed_at = (Get-Date).ToUniversalTime().ToString('o')
        capture_engine = 'tshark'
        capture_driver = 'npcap'
    }
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 (Join-Path $dir 'deployment.json')
}

Assert-Administrator
Write-Host '============================================================'
Write-Host ' MON - Native Windows Installation'
Write-Host '============================================================'

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'This branch supports native Windows only. Do not run it inside WSL.'
}

Ensure-Python
Ensure-WiresharkNpcap

Write-Host '[MON] Building Windows executable...'
if ($SkipBuildTests) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\build_windows.ps1 -SkipTests
} else {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\build_windows.ps1
}
if ($LASTEXITCODE -ne 0) { throw 'Windows build failed.' }

Write-Host '[MON] Installing Windows service...'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\install_windows_service.ps1
if ($LASTEXITCODE -ne 0) { throw 'Windows service installation failed.' }

Write-DeploymentManifest
Start-Sleep -Seconds 5

Write-Host '[MON] Verifying runtime...'
& py.exe -3.12 -c "import sys; sys.path.insert(0, r'$Root\src'); from campus_ops.deployment_check import main; main()"
if ($LASTEXITCODE -ne 0) {
    Write-Warning 'MON installed, but readiness verification is not yet READY. Run .\scripts\diagnose_windows.ps1.'
    exit 2
}

Write-Host ''
Write-Host 'MON is READY.'
Write-Host 'Open: http://127.0.0.1:8765'
