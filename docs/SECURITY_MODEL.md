# MON Windows 1.0 Security Model

## Scope

MON Windows is a defensive passive network monitor. It captures packet metadata visible
to one selected Windows adapter using one TShark process through Npcap. It does not
actively scan hosts, open remote shells, quarantine endpoints, decrypt TLS or claim
traffic that the selected adapter did not receive.

## Local service boundary

The packaged runtime is installed as the Windows service `MONWindows`. The HTTP console
and API bind to `127.0.0.1` by default. Browser opening is disabled for the service;
operators open the local console in their own desktop session.

The service is configured with delayed automatic start and recovery restarts. The
installer removes the previous legacy MON service name to prevent two collectors from
competing for port 8765 or the same capture adapter.

## Packet capture boundary

Npcap is the packet-capture driver and TShark is the only MON-managed packet process.
The selected Windows alias is resolved to an adapter GUID and then to the Npcap capture
device. MON records the operator-facing adapter name separately from the capture device
so Watchdog can verify alignment.

Quiet packet intervals do not imply link or process failure. A real TShark process exit,
missing PID, wrong backend or adapter mismatch is surfaced as a runtime fault.

## Evidence integrity / anti-fabrication rules

MON separates observation from assertion:

- arbitrary text typed into Investigation does not create an asset;
- local assets require repeated source-frame evidence and a valid unicast source MAC;
- flows require packet-observed local participation;
- topology edges require TShark packet evidence;
- remote packet peers can be displayed as peers without being called local assets;
- unseen IPs are refused by the operator investigation endpoint;
- no physical network hop is asserted without evidence.

A priority score is an evidence-based investigation priority, not a declaration that a
host is malicious or safe.

## Data minimization

Current packet/live state is kept in bounded memory. A local SQLite history at
`C:\ProgramData\MON\evidence.db` stores security/control events and aggregate asset/flow
snapshots for investigation continuity. Default retention is seven days and tables have
row limits.

The history worker does not deliberately store raw packet payloads or PCAP. The product
does not decrypt TLS. Application context is limited to metadata that can be observed in
the packet stream, such as protocol fields, DNS names, TLS SNI where exposed, and HTTP
host metadata where exposed.

## Operator surface

The local console exposes Overview, Network, Topology, Path Space, Security,
Investigation, System and Watchdog. There is no Admin panel, active-probe workspace,
Nmap/tool hub, endpoint-isolation control or remote-command function in this branch.

FastAPI interactive docs/OpenAPI endpoints are disabled in the packaged local runtime.

## Persistent sensor identity

Each installed sensor gets a persistent random `sensor_id` stored under
`C:\ProgramData\MON`. Tenant/site labels can be supplied through deployment environment
variables. These labels prepare for a future control plane; they do not authenticate a
cloud service and the current sensor does not transmit data to one.

## SaaS requirements not yet satisfied by this local sensor

Before MON is sold as a hosted multi-tenant service, the cloud plane needs an independent
security review and at minimum:

- cryptographically authenticated sensor enrollment and rotation;
- TLS for every network path and preferably mutual sensor authentication;
- strong tenant isolation at API, storage, query and background-job layers;
- organization/user RBAC and MFA/SSO support;
- immutable administrative/audit events;
- centralized retention/deletion policy controls;
- encrypted managed secrets/keys;
- abuse/rate limits and ingestion quotas;
- backup/restore testing and disaster recovery;
- vulnerability/dependency management and signed release artifacts;
- production telemetry, service health monitoring and incident-response procedures.

## Visibility limitation

The evidence model is only as broad as the sensor placement. A normal switched client
port or Wi-Fi client connection generally does not receive all peer-to-peer unicast
traffic on the campus. Wider passive coverage requires an authorized mirror/SPAN/TAP or
gateway position. MON must state that boundary rather than infer hidden activity.
