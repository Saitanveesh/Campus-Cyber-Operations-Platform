> Historical expansion plan. Ubuntu implementation status and current priorities are maintained in [ARCHITECTURE.md](ARCHITECTURE.md), [TOOL_INTEGRATIONS.md](TOOL_INTEGRATIONS.md) and [RISK_REGISTER.md](RISK_REGISTER.md).

# Campus Cyber Operations Platform — Expansion Plan

This plan keeps the platform aligned to the existing architecture: Network Plane, Endpoint Plane, Control Plane, Normalization Bus, Intelligence Plane, Correlation, Response/SOAR, Evidence, and the Operator Console.

## Design rule

Every feature must answer four questions before it becomes a first-class capability:

1. What evidence does it collect or act on?
2. Which plane owns it?
3. How does it fail without creating false live data?
4. How is the operator shown uncertainty, scope, and action state?

## Priority 1 — Visibility and health

- Keep TShark + Npcap as the primary Windows live-packet path.
- Keep dumpcap as bounded PCAP-NG evidence capture.
- Use Pktmon and Windows networking commands for diagnostics/fallback evidence, not as fake replacements for decoded live traffic.
- Continue Syslog, flow export, SNMP/LLDP and Wi-Fi telemetry as independent evidence sources.
- Capability Center continuously reports which visibility paths are actually ready.

## Priority 2 — Endpoint depth

- Expand the endpoint agent with process tree, services, users/sessions, listening sockets, file changes, Windows Defender state and selected Windows Event Log channels.
- Add optional Sysmon ingestion when available.
- Add optional osquery enrichment for repeatable endpoint queries.
- Add binary trust checks through Sigcheck and persistence inspection through Autoruns when installed.

## Priority 3 — Detection and investigation

- Keep behavioural detections evidence-backed and separate from signature detections.
- Expand Suricata integration with rule/update health and alert-to-flow correlation.
- Expand malware triage with YARA, signature trust and optional ClamAV second opinion.
- Add Hayabusa/Chainsaw as optional offline or operator-triggered Windows event hunting tools.
- Correlate endpoint + network observations into one incident timeline.

## Priority 4 — Topology and identity

- Maintain a live observed-communication graph from packet/flow evidence.
- Add physical/logical hierarchy only when SNMP, LLDP, controller, DHCP or flow-export evidence supports it.
- Keep device identity confidence explicit and merge identities only with evidence.
- Add VLAN/site/switch context as infrastructure telemetry becomes available.

## Priority 5 — Response and SOAR

- Preserve policy-gated actions and role checks.
- Finish isolate/restore host, stop process, quarantine file, block policy request and evidence snapshot workflows.
- Require explicit operator authorization for active discovery and disruptive actions.
- Add playbooks that propose actions first and execute only when policy permits.
- Record every action, result, actor, target and evidence reference.

## Priority 6 — Evidence and deployment

- Generate incident bundles containing timeline, hashes, relevant alerts, topology/flow snapshots, endpoint snapshots and PCAP references.
- Add chain-of-custody hashes and export manifests.
- Run as a resilient Windows service with restart/recovery behaviour.
- Produce a signed installer only after clean-machine and long-run validation.

## Tool strategy

### Core / high value

Npcap, TShark, dumpcap, PowerShell, wevtutil, netsh, Pktmon, Suricata, YARA.

### Optional enrichment

Sysmon, osquery, Nmap, Sigcheck, Autoruns CLI, Handle, ClamAV, Hayabusa, Chainsaw.

Optional tools must never make the core monitor unusable. Missing optional tooling appears as a capability gap, not synthetic data.

## Validation gate

Before calling the platform complete, validate:

- no-network boot and later connection
- disconnect/reconnect and Wi-Fi/Ethernet switching
- IP/subnet/gateway changes
- long idle link and heavy traffic
- collector/tool failure and recovery
- endpoint agent loss and recovery
- incident open/escalate/acknowledge/close/reopen
- response job success/failure/stall
- old session data never reappears in a new live session
- all assistant statements match current evidence
- clean-machine installer and Windows service restart
