param(
    [string]$ServiceName = 'CampusCyberOperationsPlatform',
    [string]$DisplayName = 'Campus Cyber Operations Platform',
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $root 'dist\CampusCyberOperationsPlatform.exe'

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

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run PowerShell as Administrator to install the Windows service.'
}

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

$bin = '"' + $exe + '"'
sc.exe create $ServiceName binPath= $bin start= auto DisplayName= $DisplayName | Out-Null
sc.exe description $ServiceName 'Campus cyber operations monitoring service' | Out-Null
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/15000/restart/30000 | Out-Null
Start-Service -Name $ServiceName

Write-Host "Installed and started $ServiceName"
Write-Host "Executable: $exe"
Write-Host 'Note: service-mode browser launch should be disabled with CAMPUS_OPS_NO_BROWSER=1 in the service environment.'
