# Campus Cyber Operations Platform

Windows-native cyber operations platform for authorized cyber-range and campus-lab environments.

## Product direction

The platform unifies network visibility, protocol and flow intelligence, asset state, topology, performance, threat detection, malware analysis, incident correlation, endpoint control, evidence handling, and operator alerting behind one strict monochrome interface.

### Frozen UI direction

Black / white / grey only. No colorful SOC theme. The UI is evidence-first and topology-centric.

### Safety and trust model

- Current-session-only live state. Historical state never silently appears as live.
- Fail closed when capture, storage, API, or worker health is uncertain.
- Remote host actions are only for explicitly enrolled/authorized lab systems.
- All response actions are auditable and permission-gated.
- Detections are evidence-backed indicators; the platform does not manufacture certainty.

## Foundation v1

This repository currently provides the product foundation:

- typed event model and in-process event bus
- supervised worker runtime with health states
- Windows-aware network auto-discovery worker
- external-tool registry for Npcap/dumpcap/TShark/Suricata/YARA
- unified orchestrator
- FastAPI status surface
- monochrome operator console shell
- Windows CI tests

Future workers plug into the same contracts rather than becoming independent scripts.

## Development

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .[dev]
python -m campus_ops
```

Open `http://127.0.0.1:8765`.

## Planned worker families

`capture` · `protocol` · `flow` · `asset` · `performance` · `topology` · `ids` · `behavior` · `malware` · `endpoint` · `response` · `incident` · `forensics` · `voice` · `storage` · `system-health`
