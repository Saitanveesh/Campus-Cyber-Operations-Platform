# Architecture v1

## Mission

Campus Cyber Operations Platform is a Windows-native, evidence-first cyber operations system for authorized cyber-range and campus-lab environments. It is not a single packet monitor. It combines independent specialist workers under one supervisor and one live-state contract.

## Control model

```text
Operator Console
      |
      v
API / Command Gateway
      |
      v
Orchestrator / Supervisor
      |
      +-- Session Manager
      +-- Event Bus
      +-- Tool Registry
      +-- Worker Health
      +-- Policy / Authorization
      |
      +-- Network Auto-Discovery Worker
      +-- Capture Worker            -> Npcap / dumpcap
      +-- Protocol Worker           -> TShark / native decoders
      +-- Flow Worker
      +-- Asset Worker
      +-- Performance Worker
      +-- Topology Worker
      +-- IDS Worker                -> Suricata
      +-- Behaviour Worker
      +-- Malware Worker            -> YARA / IOC adapters
      +-- Endpoint Worker           -> enrolled agents only
      +-- Response Worker           -> permission gated
      +-- Incident Correlator
      +-- Evidence Worker
      +-- Voice / Siren Worker
      +-- Storage Worker
```

## Why multiple workers

Each worker owns one responsibility and exchanges typed events. External tools are adapters, not the application architecture. If one tool is unavailable, the supervisor reports a degraded capability instead of fabricating data.

Examples:

- dumpcap/Npcap: privileged packet acquisition
- TShark: deep protocol decoding
- Suricata: mature signature/IDS telemetry
- YARA: file-content rules where a file is legitimately extracted
- native workers: session truth, correlation, topology, baselines, evidence, UI contracts

## Live-state contract

1. Exactly one active live session exists at a time.
2. A network identity change closes the old session before a new one opens.
3. Live API responses include the current session id.
4. Historical records are never used as fallback values for live fields.
5. Worker failure produces `DEGRADED` or `FAILED`, never frozen stale values presented as healthy.
6. Every observation carries source worker, timestamp, session id, and evidence class.

## Network auto-discovery

The platform elects a capture interface from host-local evidence:

- adapter operational state
- usable unicast IPv4/IPv6
- default route ownership
- route metric
- loopback/virtual/tunnel classification
- traffic counters
- known capture backend visibility
- hysteresis to prevent interface flapping

Manual interface pinning will be supported, but automatic election is the default.

## Visibility levels

The UI must always disclose what evidence is actually available.

- Access-port mode: host traffic plus broadcasts/multicasts visible to the endpoint
- SPAN/TAP mode: mirrored packet visibility for the configured scope
- Flow mode: NetFlow/IPFIX/sFlow summaries
- Infrastructure mode: SNMP/LLDP/syslog/network-controller telemetry
- Endpoint mode: enrolled-agent host evidence

The system never labels access-port observations as full campus visibility.

## Endpoint control

Remote access and response are separate from passive visibility. Only explicitly enrolled or lab-authorized systems may accept control actions. Actions are authenticated, authorization-gated, logged, and tied to an operator identity and incident context.

## UI direction

Monochrome only: black, white, grey, borders, typography, motion and density convey state. The topology is an operational graph, not decoration.

Planned views:

- Overview
- Physical / Logical / Communication / Security Topology
- Assets
- Traffic / Protocols / TCP / DNS
- Performance
- Security / Malware
- Incidents
- Endpoint Control
- Packets / Evidence
- History
- System Health

## Build strategy

Foundation -> capture/session -> protocols/flows -> assets/performance -> topology -> IDS/behaviour -> malware -> endpoint agent/control -> incidents -> evidence -> voice/siren -> cyber-range integration -> installer/hardening.
