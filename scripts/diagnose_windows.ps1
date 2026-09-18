$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

function Section([string]$Name) {
    Write-Host ''
    Write-Host ('=' * 72)
    Write-Host $Name
    Write-Host ('=' * 72)
}

function JsonGet([string]$Url) {
    try {
        $value = Invoke-RestMethod -Uri $Url -TimeoutSec 5 -Method Get
        $value | ConvertTo-Json -Depth 12
    } catch {
        Write-Host "ERROR: $($_.Exception.Message)"
    }
}

Section 'MON WINDOWS DIAGNOSTIC SNAPSHOT'
Write-Host "Time: $((Get-Date).ToUniversalTime().ToString('o'))"
Write-Host "Computer: $env:COMPUTERNAME"
Write-Host "Windows: $([Environment]::OSVersion.VersionString)"
try { Write-Host "Branch: $(git branch --show-current)"; Write-Host "Commit: $(git rev-parse HEAD)" } catch {}

Section 'WINDOWS ADAPTERS'
Get-NetAdapter -ErrorAction SilentlyContinue | Sort-Object Name | Format-Table Name,Status,LinkSpeed,MacAddress,InterfaceDescription -AutoSize

Section 'IP CONFIGURATION'
Get-NetIPConfiguration -ErrorAction SilentlyContinue | Format-List InterfaceAlias,InterfaceDescription,IPv4Address,IPv4DefaultGateway,DNSServer

Section 'DEFAULT ROUTES'
Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Format-Table InterfaceAlias,NextHop,RouteMetric,State -AutoSize

Section 'NEIGHBOR CACHE'
Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {$_.State -ne 'Unreachable'} | Select-Object -First 80 InterfaceAlias,IPAddress,LinkLayerAddress,State | Format-Table -AutoSize

Section 'NPCAP'
$npcap = Get-Service npcap -ErrorAction SilentlyContinue
if ($npcap) { $npcap | Format-List Name,Status,StartType } else { Write-Host 'Npcap service: NOT INSTALLED' }

Section 'TSHARK'
$tshark = Get-Command tshark.exe -ErrorAction SilentlyContinue
if (-not $tshark -and (Test-Path 'C:\Program Files\Wireshark\tshark.exe')) {
    $tshark = Get-Item 'C:\Program Files\Wireshark\tshark.exe'
}
if ($tshark) {
    $path = if ($tshark.PSObject.Properties['Source']) {$tshark.Source} else {$tshark.FullName}
    Write-Host "Path: $path"
    & $path --version | Select-Object -First 3
    Write-Host 'Capture interfaces:'
    & $path -D
} else {
    Write-Host 'TShark: NOT FOUND'
}

Section 'MON WINDOWS SERVICE'
Get-Service MONWindows -ErrorAction SilentlyContinue | Format-List Name,Status,StartType
sc.exe query MONWindows

Section 'MON PROCESSES'
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {$_.Name -in @('MONWindows.exe','tshark.exe')} | Select-Object ProcessId,ParentProcessId,Name,CommandLine | Format-List

Section 'LIVE STATUS'
JsonGet 'http://127.0.0.1:8765/api/v1/live/status'

Section 'WATCHDOG'
JsonGet 'http://127.0.0.1:8765/api/v1/system/watchdog'

Section 'SYSTEM DIAGNOSTICS'
JsonGet 'http://127.0.0.1:8765/api/v1/system/diagnostics'

Section 'REAL OBSERVED TARGETS'
JsonGet 'http://127.0.0.1:8765/api/v1/operator/targets'

Section 'DEPLOYMENT MANIFEST'
$manifest = Join-Path $env:ProgramData 'MON\deployment.json'
if (Test-Path $manifest) { Get-Content $manifest } else { Write-Host "Missing: $manifest" }

Section 'DONE'
Write-Host 'Copy this complete output when reporting a MON Windows runtime issue.'
