param(
    [string]$ServiceName = 'MONWindows',
    [string]$DisplayName = 'MON Windows Network Monitor',
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $root 'dist\MONWindows.exe'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run PowerShell as Administrator to install or remove MON Windows service.'
}

if ($Remove) {
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $ServiceName | Out-Null
        Write-Host "Removed service $ServiceName"
    } else {
        Write-Host "Service $ServiceName is not installed"
    }
    exit 0
}

if (-not (Test-Path $exe)) {
    throw "Executable not found: $exe. Run scripts\build_windows.ps1 first."
}

# Remove the legacy pre-Windows service name if it exists so two MON runtimes can
# never compete for the same API port or capture adapter.
$legacy = 'CampusCyberOperationsPlatform'
if ($legacy -ne $ServiceName -and (Get-Service -Name $legacy -ErrorAction SilentlyContinue)) {
    Stop-Service -Name $legacy -Force -ErrorAction SilentlyContinue
    sc.exe delete $legacy | Out-Null
    Start-Sleep -Milliseconds 800
}

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

$bin = '"' + $exe + '"'
sc.exe create $ServiceName binPath= $bin start= delayed-auto DisplayName= $DisplayName | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'sc.exe create failed.' }
sc.exe description $ServiceName 'Native Windows MON: one TShark/Npcap packet source, evidence-backed network monitoring.' | Out-Null
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/15000/restart/30000 | Out-Null

$serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
New-ItemProperty `
    -Path $serviceKey `
    -Name Environment `
    -PropertyType MultiString `
    -Value @(
        'CAMPUS_OPS_NO_BROWSER=1',
        'CAMPUS_OPS_INTERFACE=auto'
    ) `
    -Force | Out-Null

Start-Service -Name $ServiceName
Start-Sleep -Seconds 2
$service = Get-Service -Name $ServiceName
if ($service.Status -ne 'Running') {
    throw "Service $ServiceName did not reach RUNNING state."
}

Write-Host "Installed and started $ServiceName"
Write-Host "Executable: $exe"
Write-Host 'Interface selection: auto (native Windows Wi-Fi/Ethernet preferred over virtual adapters)'
