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
        throw 'winget is required. Install Microsoft App Installer, then rerun bootstrap.ps1.'
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
    if ($LASTEXITCODE -ne 0) { throw 'Python 3.12 installation failed.' }
    Refresh-Path
    if (-not (Get-Command py.exe -ErrorAction SilentlyContinue)) {
        throw 'Python installed but py.exe is not yet visible. Reopen Administrator PowerShell and rerun .\bootstrap.ps1.'
    }
}

function Find-TShark {
    $command = Get-Command tshark.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $candidate = 'C:\Program Files\Wireshark\tshark.exe'
    if (Test-Path $candidate) { return $candidate }
    return $null
}

function Test-Npcap {
    $service = Get-Service -Name npcap -ErrorAction SilentlyContinue
    return ($null -ne $service)
}

function Ensure-WiresharkNpcap {
    $tshark = Find-TShark
    $npcapPresent = Test-Npcap
    if (-not $tshark -or -not $npcapPresent) {
        Write-Host ''
        Write-Host '[MON] Wireshark/TShark or Npcap is missing.'
        Write-Host '[MON] Opening the official Wireshark installer.'
        Write-Host '[MON] IMPORTANT: keep "Install Npcap" enabled in the installer.'
        Write-Host ''
        Ensure-Winget
        # Wireshark's fully silent installer intentionally does not install Npcap.
        # Use the normal installer so the bundled Npcap option is available and enabled.
        winget install --id WiresharkFoundation.Wireshark -e --interactive --force --accept-package-agreements --accept-source-agreements
        if ($LASTEXITCODE -ne 0) { throw 'Wireshark installation failed.' }
        Refresh-Path
        $tshark = Find-TShark
        $npcapPresent = Test-Npcap
    }
    if (-not $tshark) {
        throw 'TShark was not found after Wireshark installation.'
    }
    if (-not $npcapPresent) {
        throw 'Npcap is still missing. Rerun the Wireshark installer and enable Install Npcap.'
    }

    $npcap = Get-Service -Name npcap -ErrorAction SilentlyContinue
    if ($npcap -and $npcap.Status -ne 'Running') {
        try { Start-Service npcap -ErrorAction Stop } catch {}
    }

    $interfaces = & $tshark -D 2>&1
    if ($LASTEXITCODE -ne 0 -or -not $interfaces) {
        throw 'TShark cannot enumerate Npcap capture adapters. Repair Npcap and rerun bootstrap.ps1.'
    }
    $realRows = @($interfaces | Where-Object { $_ -notmatch 'loopback|sshdump|randpkt|udpdump' })
    if ($realRows.Count -eq 0) {
        throw 'TShark enumerated no usable Windows capture adapters.'
    }
    Write-Host "[MON] TShark: $tshark"
    Write-Host '[MON] Npcap is installed and TShark can enumerate capture adapters.'
}

function Write-DeploymentManifest {
    $dir = Join-Path $env:ProgramData 'MON'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $commit = try { (git rev-parse HEAD 2>$null).Trim() } catch { '' }
    $branch = try { (git branch --show-current 2>$null).Trim() } catch { '' }
    $manifest = [ordered]@{
        installed = $true
        profile = 'windows-native-single-source'
        version = '1.0.0-windows'
        branch = $branch
        commit = $commit
        installed_at = (Get-Date).ToUniversalTime().ToString('o')
        capture_engine = 'tshark'
        capture_driver = 'npcap'
        ip_truth_policy = 'current-session-packet-evidence-only'
    }
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 (Join-Path $dir 'deployment.json')
}

Assert-Administrator
Write-Host '============================================================'
Write-Host ' MON Windows - Native Installer'
Write-Host ' TShark + Npcap / current packet evidence only'
Write-Host '============================================================'

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'This branch is Windows-only. Run it from Windows PowerShell, not WSL.'
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
Start-Sleep -Seconds 6

Write-Host '[MON] Verifying adapter/session/TShark runtime...'
& py.exe -3.12 -c "import sys; sys.path.insert(0, r'$Root\src'); from campus_ops.deployment_check import main; main()"
if ($LASTEXITCODE -ne 0) {
    Write-Warning 'MON installed, but readiness is not READY. Run .\scripts\diagnose_windows.ps1 and fix the first reported failure.'
    exit 2
}

Write-Host ''
Write-Host 'MON Windows is READY.'
Write-Host 'Console: http://127.0.0.1:8765'
Start-Process 'http://127.0.0.1:8765'
