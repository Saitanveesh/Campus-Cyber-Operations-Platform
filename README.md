# Campus Cyber Operations Platform

Ubuntu-first cyber operations platform for authorized campus and lab environments. The existing black/white/grey operational console is preserved.

## Current Ubuntu increment

- Native Linux route/interface discovery, systemd service inventory and shared XDG/service state paths.
- Single Zeek JSON reader and syslog listener, with bounded live-only sensor tailing.
- Local export adapters for Tetragon, Falco, Wazuh, OpenCanary and Hubble.
- SQLite evidence graph, source lineage, durable deduplication and separate risk/confidence heuristics.
- Observe mode by default; optional governed snapshots of online enrolled endpoints.
- Admin-authenticated validation windows that match expected alerts without claiming attack causality or measured coverage.
- Ubuntu installer/service and Python 3.12/3.13 CI. Actual sensor deployment and Linux containment remain unvalidated/unimplemented respectively.

## Start on Ubuntu

```bash
sudo bash scripts/install_ubuntu.sh
```

Open http://127.0.0.1:8765. Read [deployment instructions](docs/UBUNTU_DEPLOYMENT.md) before configuring sensor exports.

## Development

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m pip install --no-deps -e .
.venv/bin/ruff check src tests
.venv/bin/pytest -q
CAMPUS_OPS_NO_BROWSER=1 .venv/bin/python -m campus_ops
```

## Architecture and scope

[Architecture](docs/ARCHITECTURE.md) · [Integration status](docs/TOOL_INTEGRATIONS.md) · [Risk register](docs/RISK_REGISTER.md)

Installed binaries and registry entries are not proof of operational integration. Most tools in the planned ecosystem still need connectors. Historical evidence never silently becomes live evidence, and response control remains limited to explicitly enrolled endpoints.
