param(
    [int]$Samples = 6,
    [int]$IntervalSeconds = 5
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$Base = 'http://127.0.0.1:8765'
$Failures = New-Object System.Collections.Generic.List[string]
$Warnings = New-Object System.Collections.Generic.List[string]

function Pass([string]$Message) { Write-Host "[PASS] $Message" -ForegroundColor Green }
function Fail([string]$Message) { $Failures.Add($Message); Write-Host "[FAIL] $Message" -ForegroundColor Red }
function Warn([string]$Message) { $Warnings.Add($Message); Write-Host "[WARN] $Message" -ForegroundColor Yellow }

Write-Host '============================================================'
Write-Host ' MON Windows - End-to-End Self Test'
Write-Host '============================================================'

$service = Get-Service MONWindows -ErrorAction SilentlyContinue
if ($service -and $service.Status -eq 'Running') { Pass 'MONWindows service is RUNNING' } else { Fail 'MONWindows service is not RUNNING' }

$npcap = Get-Service npcap -ErrorAction SilentlyContinue
if ($npcap -and $npcap.Status -eq 'Running') { Pass 'Npcap service is RUNNING' } else { Fail 'Npcap service is missing or not RUNNING' }

$tshark = 'C:\Program Files\Wireshark\tshark.exe'
if (Test-Path $tshark) {
    Pass 'TShark executable exists'
    $interfaces = @(& $tshark -D 2>&1)
    if ($LASTEXITCODE -eq 0 -and $interfaces.Count -gt 0) { Pass "TShark enumerated $($interfaces.Count) capture interface(s)" } else { Fail 'TShark could not enumerate Npcap interfaces' }
} else {
    Fail "TShark missing at $tshark"
}

try {
    $status = Invoke-RestMethod "$Base/api/v1/live/status" -TimeoutSec 5
    Pass 'MON local API responded'
} catch {
    Fail "MON local API unavailable: $($_.Exception.Message)"
    $status = $null
}

if ($status) {
    if ($status.runtime_profile -eq 'windows-native-single-source') { Pass 'Windows-native runtime profile is active' } else { Fail "Unexpected runtime profile: $($status.runtime_profile)" }
    if ($status.ip_truth_policy -eq 'current-session-packet-evidence-only') { Pass 'Packet-evidence IP truth policy is active' } else { Fail 'Packet-evidence IP truth policy is missing' }
    if ($status.session_id) { Pass "Monitoring session exists: $($status.session_id)" } else { Fail 'Monitoring session ID is empty' }
    if ($status.network.interface) { Pass "Selected Windows adapter: $($status.network.interface)" } else { Fail 'No selected Windows adapter' }

    $capture = $status.live.capture
    if ($capture.state -eq 'ACTIVE') { Pass 'Capture state is ACTIVE' } else { Fail "Capture state is $($capture.state): $($capture.detail)" }
    if ($capture.backend -eq 'tshark') { Pass 'Capture backend is TShark' } else { Fail "Capture backend is $($capture.backend)" }
    if ([int]($capture.process_pid ?? 0) -gt 0) { Pass "Managed TShark PID: $($capture.process_pid)" } else { Fail 'Managed TShark PID is missing' }
    if ($capture.interface -and $status.network.interface -and $capture.interface.ToString().ToLowerInvariant() -eq $status.network.interface.ToString().ToLowerInvariant()) { Pass 'Network and capture adapters agree' } else { Fail "Adapter mismatch: network=$($status.network.interface) capture=$($capture.interface)" }
}

try {
    $watchdog = Invoke-RestMethod "$Base/api/v1/system/watchdog" -TimeoutSec 5
    if ($watchdog.state -eq 'HEALTHY') { Pass 'Watchdog state is HEALTHY' } else { Fail "Watchdog state is $($watchdog.state)" }
} catch {
    Fail "Watchdog API failed: $($_.Exception.Message)"
}

try {
    $diagnostics = Invoke-RestMethod "$Base/api/v1/system/diagnostics" -TimeoutSec 5
    if ([int]$diagnostics.problem_count -eq 0) { Pass 'Deterministic diagnostics report no runtime fault' } else {
        Fail "Diagnostics reports $($diagnostics.problem_count) problem(s)"
        $diagnostics.problems | ForEach-Object { Write-Host "       $($_.problem): $($_.evidence)" }
    }
} catch {
    Fail "Diagnostics API failed: $($_.Exception.Message)"
}

try {
    $sensor = Invoke-RestMethod "$Base/api/v1/system/sensor" -TimeoutSec 5
    if ($sensor.sensor_id) { Pass "Persistent sensor identity: $($sensor.sensor_id)" } else { Fail 'Sensor identity is missing' }
} catch {
    Fail "Sensor identity API failed: $($_.Exception.Message)"
}

# Anti-fabrication regression: a reserved documentation address that has not been seen
# must not receive a synthetic investigation report. The API contract is HTTP 404.
$fakeIp = '198.51.100.254'
$fakeRejected = $false
try {
    $null = Invoke-RestMethod "$Base/api/v1/operator/investigate/$fakeIp" -TimeoutSec 5
} catch {
    $response = $_.Exception.Response
    if ($response -and [int]$response.StatusCode -eq 404) { $fakeRejected = $true }
}
if ($fakeRejected) { Pass 'Unseen IP investigation is refused (HTTP 404)' } else { Fail 'Unseen IP was not refused; anti-fabrication contract failed' }

try {
    $targets = Invoke-RestMethod "$Base/api/v1/operator/targets" -TimeoutSec 5
    $count = @($targets.targets).Count
    Pass "Observed-target API returned $count current packet-evidence target(s)"
    if ($count -eq 0) { Warn 'No packet-observed target exists yet; generate ordinary local traffic and refresh before a demo' }
} catch {
    Fail "Observed-target API failed: $($_.Exception.Message)"
}

# Soak invariant: while Windows networking stays connected, the session, selected alias,
# and TShark PID should not oscillate. Packet count may remain unchanged when traffic is quiet.
$sessionSet = New-Object System.Collections.Generic.HashSet[string]
$adapterSet = New-Object System.Collections.Generic.HashSet[string]
$pidSet = New-Object System.Collections.Generic.HashSet[string]
$previousPackets = -1
for ($i = 1; $i -le [Math]::Max(1,$Samples); $i++) {
    try {
        $sample = Invoke-RestMethod "$Base/api/v1/live/status" -TimeoutSec 5
        [void]$sessionSet.Add([string]$sample.session_id)
        [void]$adapterSet.Add([string]$sample.network.interface)
        [void]$pidSet.Add([string]$sample.live.capture.process_pid)
        $packets = [int64]($sample.live.capture.packets ?? 0)
        if ($previousPackets -ge 0 -and $packets -lt $previousPackets) { Fail "Packet counter moved backwards: $previousPackets -> $packets" }
        $previousPackets = $packets
        Write-Host ("[SOAK {0}/{1}] session={2} adapter={3} pid={4} state={5} activity={6} packets={7}" -f $i,$Samples,$sample.session_id,$sample.network.interface,$sample.live.capture.process_pid,$sample.live.capture.state,$sample.live.capture.traffic_activity,$packets)
    } catch {
        Fail "Soak sample $i failed: $($_.Exception.Message)"
    }
    if ($i -lt $Samples) { Start-Sleep -Seconds ([Math]::Max(1,$IntervalSeconds)) }
}
if ($sessionSet.Count -eq 1) { Pass 'Session ID remained stable during soak' } else { Fail "Session ID oscillated during soak: $($sessionSet.Count) values" }
if ($adapterSet.Count -eq 1) { Pass 'Selected adapter remained stable during soak' } else { Fail "Selected adapter oscillated during soak: $($adapterSet.Count) values" }
if ($pidSet.Count -eq 1) { Pass 'TShark PID remained stable during soak' } else { Fail "TShark PID oscillated during soak: $($pidSet.Count) values" }

Write-Host ''
if ($Warnings.Count -gt 0) {
    Write-Host "Warnings: $($Warnings.Count)" -ForegroundColor Yellow
    $Warnings | ForEach-Object { Write-Host " - $_" }
}
if ($Failures.Count -gt 0) {
    Write-Host "MON SELF TEST: FAIL ($($Failures.Count) failure(s))" -ForegroundColor Red
    $Failures | ForEach-Object { Write-Host " - $_" }
    exit 2
}
Write-Host 'MON SELF TEST: PASS' -ForegroundColor Green
exit 0
