# MON Windows 1.0 Architecture

## Product boundary

MON Windows is a native Windows network monitoring sensor and local operator console.
It is not an endpoint EDR, active scanner, firewall or full cloud SIEM. The sensor's
core promise is narrower: derive explainable network evidence from one packet source,
keep the collection path healthy, and make that evidence useful for investigation.

## Data plane

```text
Windows Wi-Fi / Ethernet
        |
 Windows network election
        |
 alias -> InterfaceGuid -> Npcap device
        |
      TShark                 one managed capture process
        |
 normalized packet observations
        |
      EventBus
        |
  +-----+------------------------------+
  |     |       |       |              |
asset  flow  topology protocols   DNS/service/TCP
  |     |       |       |              |
  +-----+-------+-------+--------------+
        |
behavior / baseline / ARP / beacon / DoS
        |
alerts -> incident correlation
        |
LiveState + bounded metadata EvidenceStore
        |
Windows API -> operator console
```

TShark through Npcap is the only packet acquisition path. MON does not start a second
collector, IDS engine or scanner. All relationship/security views use the same packet
observations so one UI cannot silently disagree with another because of a separate data
pipeline.

## Windows network control plane

`WindowsNetworkDiscoveryWorker` uses native Windows routing/adapter information to
select one usable adapter. It combines `Get-NetAdapter`, `Get-NetRoute`,
`Get-NetIPInterface`, and local interface statistics. Physical routed Wi-Fi/Ethernet is
preferred over Hyper-V, WSL, VPN and other virtual adapters.

Windows route selection considers route metric plus interface metric. Interface changes
and network-identity changes require repeated confirmation. Several consecutive missing
observations are required before an active session is torn down. Temporary IPv6 privacy
address rotation does not reset an IPv4 session.

The session manager subscribes only to network-control events. High packet volume can
therefore cause a slow analysis consumer to drop data without displacing an adapter or
session transition.

## Capture binding

`WindowsCaptureWorker` resolves the selected Windows adapter alias to its
`InterfaceGuid`, then matches that GUID to TShark/Npcap's capture interface. This is
preferred to fuzzy matching text such as `Wi-Fi` because multiple adapters can have
similar descriptions.

Capture health is process-based:

- `ACTIVE` means the managed TShark process is alive and bound.
- `traffic_activity=PACKETS` means recent packets arrived.
- `traffic_activity=QUIET` means the wire was quiet while TShark remained healthy.
- a real process exit is `ERROR` and is surfaced by Watchdog/System diagnostics.

## Evidence truth model

A syntactically valid IP address is not proof of a host.

Local asset promotion requires:

1. a packet from the current session;
2. an IP inside the selected local network (or the sensor/gateway identity);
3. a valid unicast source MAC; and
4. repeated source-frame observations.

Remote addresses can appear as packet-observed peers when a real packet contains them,
but they are not promoted to local assets. Typed/unseen IPs are rejected by the
Investigation route instead of receiving a risk or safety verdict.

Topology uses packet observations only. Path Space presents observed communication
relationships plus the configured Windows gateway as a routing boundary. A configured
gateway is context, not proof of a measured physical hop. Physical switch/router paths
are never invented.

## Analysis layer

The Windows runtime currently includes deterministic, evidence-backed components for:

- protocol/application/DNS/service/TCP context;
- per-asset and per-flow traffic behavior;
- ARP ownership change detection;
- SYN fan-out / reconnaissance-like behavior;
- DNS rate anomalies;
- periodic/beacon-like communication;
- DoS/traffic pressure warnings;
- baseline/performance telemetry;
- alert deduplication and incident correlation.

The design intentionally does not make an AI model the source of truth. A future AI
assistant may summarize established evidence, but asset existence, packet relationships,
alerts and runtime health remain deterministic.

## History and investigation

Live state is current-session-only. For investigations, `EvidenceStoreWorker` writes a
bounded SQLite history in `C:\ProgramData\MON\evidence.db`:

- security/control events;
- periodic aggregate asset snapshots; and
- periodic aggregate flow snapshots.

Default retention is seven days with row limits. This worker does not retain raw packet
payloads or PCAP.

Investigation correlates the current live asset/flow/topology/alert/incident evidence and
adds recent historical metadata for a target that is already proven by the current
TShark session.

## Runtime supervision

Watchdog/System checks the sensor itself as part of the monitoring contract:

- native-Windows execution;
- selected adapter and active session;
- TShark backend/PID/capture device;
- network/capture adapter alignment;
- analysis worker health;
- event-bus drops; and
- evidence-store health.

Each detected fault is returned as `problem`, `evidence`, `cause`, `fix`, and `verify`
rather than as a generic red status.

## UI contract

The Windows console intentionally exposes only:

`Overview · Network · Topology · Path Space · Security · Investigation · System · Watchdog`

There is no Admin panel, active-probe console, Nmap/tool hub, quarantine panel or remote
shell. Browser voice is a local notification aid and is not another telemetry pipeline.

## SaaS evolution boundary

The branch contains a persistent `sensor_id` and optional tenant/site labels so a later
cloud control plane has a stable local identity. That does not make the current branch a
production SaaS service. A hosted product still needs separately reviewed authenticated
sensor enrollment, mutually authenticated/TLS transport, tenant isolation, RBAC, audit
logs, cloud retention controls, secret rotation, rate limiting, backups, monitoring and
incident-response processes.
