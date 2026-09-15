# Campus Cyber Operations Platform

Ubuntu-first cyber operations platform for authorized campus and lab environments. The existing black/white/grey operational console is preserved.

## Current Ubuntu increment

- Native Linux route/interface discovery, systemd service inventory and shared XDG/service state paths.
- Single Zeek JSON reader and syslog listener, with bounded live-only sensor tailing.
- Local export adapters for Tetragon, Falco, Wazuh, OpenCanary and Hubble.
- SQLite evidence graph, source lineage, durable deduplication and separate risk/confidence heuristics.
- Observe mode by default; optional governed snapshots of online enrolled endpoints.
- Admin-authenticated validation windows that match expected alerts without claiming attack causality or measured coverage.
- Full Ubuntu bootstrap: packet tools, managed Zeek/Suricata, OpenCanary and kernel-compatible Falco, with systemd supervision and live deployment status.
- Ethernet/Wi-Fi/USB/VPN discovery, unplug failover, explicit tap/SPAN selection and Linux `any` capture.
- Python 3.12/3.13 tests and full installation checks on Ubuntu 22.04/24.04. Linux containment remains disabled.

## Start on Ubuntu

```bash
git clone --branch monitor-v1 --single-branch https://github.com/Saitanveesh/Campus-Cyber-Operations-Platform.git
cd Campus-Cyber-Operations-Platform
sudo bash scripts/install_ubuntu.sh --interface any
```

Open http://127.0.0.1:8765 and refresh the existing Tool Hub. Cloning downloads source; the single installer command installs prerequisites and enables services at boot. Ubuntu 22.04's Python 3.10 is left intact; the installer supplies a separate Python 3.12 runtime. Use `--interface auto` to follow the preferred routed link instead of capturing all Linux-visible interfaces. See [deployment instructions](docs/UBUNTU_DEPLOYMENT.md) for WSL, profiles and service health.

## Development

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/ruff check src tests
.venv/bin/pytest -q
CAMPUS_OPS_NO_BROWSER=1 .venv/bin/python -m campus_ops
```

## Architecture and scope

[Architecture](docs/ARCHITECTURE.md) · [Integration status](docs/TOOL_INTEGRATIONS.md) · [Risk register](docs/RISK_REGISTER.md)

Installed binaries and registry entries are not proof of operational integration. Most tools in the planned ecosystem still need connectors. Historical evidence never silently becomes live evidence, and response control remains limited to explicitly enrolled endpoints.
