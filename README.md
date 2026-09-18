# MON Windows 1.0

Native Windows network monitoring sensor and operator console for schools, colleges and small campus environments.

Branch: `windows-native-v2`

## Product contract

MON Windows is deliberately narrow and evidence-driven:

- Native Windows only. Do not run it in WSL.
- One packet source: **TShark through Npcap**.
- One elected Windows Wi-Fi/Ethernet adapter per monitoring session.
- Assets, flows, topology, security conditions and investigations come from the same packet stream.
- Investigation targets must have current-session packet evidence. Typing an arbitrary IP does not create a host or a risk verdict.
- Local assets require repeated source-frame evidence and a valid unicast source MAC.
- Physical switch/router hops are never invented.
- Quiet traffic does not mark capture down.
- No Admin panel, remote shell, active scanner, Nmap console, Zeek, Suricata, secondary packet pipeline or endpoint-control stack.
- Local history stores metadata only. Raw packet payloads/PCAP are not retained by the history worker.

Primary console:

`Overview · Network · Topology · Path Space · Security · Investigation · System · Watchdog`

Browser voice alerts can be enabled locally for high-priority security/runtime conditions.

## What the sensor can actually see

A Windows machine on a normal switched Wi-Fi/Ethernet access connection generally sees its own traffic plus broadcast/multicast traffic delivered to it. It does **not** automatically see every other client on the campus LAN.

For a school/college deployment that needs broader network visibility, place the Windows sensor where traffic is legitimately delivered to it, for example a managed-switch SPAN/mirror destination, an approved TAP, or a Windows gateway/bridge position. MON reports the evidence available at its selected adapter; it does not claim invisible traffic.

## Fresh Windows installation

Open **PowerShell as Administrator**:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

cd $HOME\Desktop
git clone --branch windows-native-v2 --single-branch https://github.com/Saitanveesh/Campus-Cyber-Operations-Platform.git MON-Windows
cd .\MON-Windows

.\bootstrap.ps1
```

`bootstrap.ps1` verifies/installs the required Windows prerequisites, builds `MONWindows.exe`, installs the `MONWindows` service, starts it, and runs the readiness gate.

If Wireshark/Npcap is missing, the normal Wireshark installer is opened. Keep **Install Npcap** enabled.

When installation finishes, open:

```text
http://127.0.0.1:8765
```

## Update an existing checkout

Administrator PowerShell:

```powershell
cd $HOME\Desktop\MON-Windows

git checkout windows-native-v2
git fetch origin
git reset --hard origin/windows-native-v2

.\bootstrap.ps1
```

## Verify the runtime

```powershell
Get-Service MONWindows
Get-Service npcap -ErrorAction SilentlyContinue

& 'C:\Program Files\Wireshark\tshark.exe' -D

Invoke-RestMethod http://127.0.0.1:8765/api/v1/live/status | ConvertTo-Json -Depth 8
Invoke-RestMethod http://127.0.0.1:8765/api/v1/system/watchdog | ConvertTo-Json -Depth 8
Invoke-RestMethod http://127.0.0.1:8765/api/v1/system/diagnostics | ConvertTo-Json -Depth 8
Invoke-RestMethod http://127.0.0.1:8765/api/v1/system/sensor | ConvertTo-Json -Depth 6
```

A healthy deployment has one non-empty session ID, one selected Windows adapter, capture state `ACTIVE`, backend `tshark`, a live TShark PID, and matching network/capture adapter names.

`traffic_activity=QUIET` is healthy when the TShark process is alive.

## One-command diagnostics

```powershell
.\scripts\diagnose_windows.ps1
```

Use this before changing capture settings. It collects Windows adapters, addresses, routes, neighbors, Npcap state, TShark interfaces, MON service state, live capture status, observed targets, watchdog output and deterministic remediation guidance.

## Real-IP investigation rule

List IPs MON has actually observed in the current TShark session:

```powershell
Invoke-RestMethod http://127.0.0.1:8765/api/v1/operator/targets | ConvertTo-Json -Depth 8
```

Investigate one of those IPs:

```powershell
$ip = 'REPLACE_WITH_AN_OBSERVED_IP'
Invoke-RestMethod "http://127.0.0.1:8765/api/v1/operator/investigate/$ip" | ConvertTo-Json -Depth 10
```

An unseen IP receives HTTP 404 with the explanation that it was not observed in current TShark evidence. MON does not fabricate an assessment.

## Evidence retention

MON keeps bounded local metadata history at:

```text
C:\ProgramData\MON\evidence.db
```

Default retention is seven days. Stored history consists of security/control events plus aggregate asset/flow snapshots. The history worker does not persist packet payloads or PCAP.

Historical metadata for a currently known IP can be queried with:

```powershell
$ip = 'REPLACE_WITH_AN_OBSERVED_IP'
Invoke-RestMethod "http://127.0.0.1:8765/api/v1/history/ip/$ip" | ConvertTo-Json -Depth 10
```

## Site/sensor identity

A persistent sensor UUID is stored under `C:\ProgramData\MON`. Optional deployment labels prepare the sensor for a future multi-tenant SaaS control plane:

```powershell
[Environment]::SetEnvironmentVariable('MON_TENANT_ID','school-001','Machine')
[Environment]::SetEnvironmentVariable('MON_SITE_ID','campus-main','Machine')
[Environment]::SetEnvironmentVariable('MON_SITE_NAME','Main Campus','Machine')
Restart-Service MONWindows
```

These labels do not send data anywhere. This branch contains the Windows sensor/operator product; a hosted multi-tenant control plane requires separate authenticated cloud enrollment and tenancy controls before production use.

## Build from source

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\build_windows.ps1
```

Output:

```text
dist\MONWindows.exe
```

The build runs Ruff, pytest and dependency validation before packaging unless `-SkipTests` is explicitly supplied.

## Service operations

```powershell
Get-Service MONWindows
Restart-Service MONWindows
Stop-Service MONWindows
Start-Service MONWindows
```

Remove the service:

```powershell
.\scripts\install_windows_service.ps1 -Remove
```

## Data and privacy posture

MON is intended to minimize data collection while still supporting network detection and investigation. The default product stores metadata, not payload content; does not decrypt TLS; does not perform active host scanning; does not create arbitrary assets from typed IPs; and exposes the operator API on localhost only.

Before offering MON as a hosted service to schools/colleges, add a separately reviewed SaaS control plane with tenant isolation, authenticated sensor enrollment, TLS transport, role-based access, audit logging, retention policy management, backups, monitoring, incident-response procedures and applicable privacy/compliance controls.
