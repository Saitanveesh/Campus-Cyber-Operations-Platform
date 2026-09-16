param(
    [string]$ServiceName = 'MONWindows',
    [string]$DisplayName = 'MON Windows Network Monitor',
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path -Parent $PSScriptRoot
$sourceExe = Join-Path $root 'dist\MONWindows.exe'
$installDir = Join-Path $env:ProgramFiles 'MON'
$installedExe = Join-Path $installDir 'MONWindows.exe'
$dataDir = Join-Path $env:ProgramData 'MON'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run PowerShell as Administrator to install or remove MON Windows service.'
}

function Remove-ServiceIfPresent([string]$Name) {
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $service) { return }
    Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
    sc.exe delete $Name | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to delete Windows service $Name." }
    for ($i = 0; $i -lt 20; $i++) {
        if (-not (Get-Service -Name $Name -ErrorAction SilentlyContinue)) { return }
        Start-Sleep -Milliseconds 250
    }
    throw "Windows service $Name did not disappear after deletion."
}

if ($Remove) {
    Remove-ServiceIfPresent $ServiceName
    Write-Host "Removed service $ServiceName"
    Write-Host "Program data was preserved at $dataDir"
    exit 0
}

if (-not (Test-Path $sourceExe)) {
    throw "Executable not found: $sourceExe. Run scripts\build_windows.ps1 first."
}

# Remove legacy service names so two MON processes cannot compete for port 8765 or the
# selected Npcap adapter.
$legacy = 'CampusCyberOperationsPlatform'
if ($legacy -ne $ServiceName) { Remove-ServiceIfPresent $legacy }
Remove-ServiceIfPresent $ServiceName

New-Item -ItemType Directory -Force -Path $installDir | Out-Null
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
Copy-Item -Path $sourceExe -Destination $installedExe -Force

if (-not (Test-Path $installedExe)) {
    throw "Installed executable is missing: $installedExe"
}
$sourceHash = (Get-FileHash $sourceExe -Algorithm SHA256).Hash
$installedHash = (Get-FileHash $installedExe -Algorithm SHA256).Hash
if ($sourceHash -ne $installedHash) {
    throw 'Installed MONWindows.exe hash does not match the built artifact.'
}

$bin = '"' + $installedExe + '"'
sc.exe create $ServiceName binPath= $bin start= delayed-auto DisplayName= $DisplayName | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'sc.exe create failed.' }
sc.exe description $ServiceName 'Native Windows MON: one TShark/Npcap packet source, evidence-backed network monitoring.' | Out-Null
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/15000/restart/30000 | Out-Null
sc.exe failureflag $ServiceName 1 | Out-Null

$serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
New-ItemProperty `
    -Path $serviceKey `
    -Name Environment `
    -PropertyType MultiString `
    -Value @(
        'CAMPUS_OPS_NO_BROWSER=1',
        'CAMPUS_OPS_INTERFACE=auto',
        "CAMPUS_OPS_DATA_DIR=$dataDir"
    ) `
    -Force | Out-Null

Start-Service -Name $ServiceName
Start-Sleep -Seconds 2
$service = Get-Service -Name $ServiceName
if ($service.Status -ne 'Running') {
    throw "Service $ServiceName did not reach RUNNING state."
}

Write-Host "Installed and started $ServiceName"
Write-Host "Executable: $installedExe"
Write-Host "SHA-256: $installedHash"
Write-Host "Data: $dataDir"
Write-Host 'Interface selection: auto (native Windows Wi-Fi/Ethernet preferred over virtual adapters)'
