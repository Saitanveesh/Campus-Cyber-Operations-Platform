# Campus Cyber Operations Platform

Linux-first cyber operations platform for authorized campus and lab environments. The existing black/white/grey operational console is preserved.

## Current monitor-v1 increment

- Native Linux route/interface discovery, systemd service inventory and shared service state paths.
- Automatic active-interface election across Ethernet, Wi-Fi, USB networking and routed Linux links; the console shows the real selected interface instead of the legacy `any` selector.
- Single Zeek JSON reader and syslog listener, with bounded live-only sensor tailing.
- Local export adapters for Tetragon, Falco, Wazuh, OpenCanary and Hubble.
- SQLite evidence graph, source lineage, durable deduplication and separate risk/confidence heuristics.
- Observe mode by default; optional governed snapshots of online enrolled endpoints.
- Admin-authenticated validation windows that match expected alerts without claiming attack causality or measured coverage.
- Packet tools, managed Zeek/Suricata, OpenCanary and kernel-compatible Falco with systemd supervision and live deployment status.
- Ethernet/Wi-Fi/USB/VPN discovery, unplug failover and explicit tap/SPAN selection.
- Python 3.12/3.13 tests and installation checks. Linux containment remains disabled unless an explicitly managed endpoint path is available.

## Fast start on Ubuntu or Kali

Clone the `monitor-v1` branch and run the repository bootstrap. It updates the branch, installs prerequisites, configures packet-capture permissions, starts the service, runs a deployment check and opens the local console when a desktop session is available.

```bash
git clone --branch monitor-v1 --single-branch https://github.com/Saitanveesh/Campus-Cyber-Operations-Platform.git
cd Campus-Cyber-Operations-Platform
bash bootstrap.sh
```

For an existing clone, use the same command again:

```bash
cd Campus-Cyber-Operations-Platform
bash bootstrap.sh
```

The default is `auto`, which follows the preferred routed physical link and will move between Ethernet and Wi-Fi when the active route changes. Use `sudo bash scripts/install_ubuntu.sh --interface NAME` only when an operator deliberately needs a fixed tap/SPAN interface. `--interface any` remains an advanced Linux capture option but is no longer the normal deployment mode.

Console: `http://127.0.0.1:8765`

## Direct installer

On supported systemd Linux hosts you can run the installer directly:

```bash
sudo bash scripts/install_ubuntu.sh --interface auto
```

If an older monitor-v1 install was configured with `CAMPUS_OPS_INTERFACE=any`, the explicit `--interface auto` command above replaces that legacy setting immediately.

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

Installed binaries and registry entries are not proof of operational integration. The System and Tool Hub views distinguish installed, listening and receiving states. Historical evidence never silently becomes live evidence, and response control remains limited to explicitly enrolled endpoints.
