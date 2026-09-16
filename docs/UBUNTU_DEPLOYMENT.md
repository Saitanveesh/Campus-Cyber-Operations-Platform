# Ubuntu Deployment — MON Stable 0.5.0

Supported host: Ubuntu 22.04 or newer with systemd.

## Fresh install

```bash
sudo apt update
sudo apt install -y git curl ca-certificates
git clone --branch monitor-v1 --single-branch https://github.com/Saitanveesh/Campus-Cyber-Operations-Platform.git
cd Campus-Cyber-Operations-Platform
bash bootstrap.sh
```

`bootstrap.sh` updates `monitor-v1` and runs `scripts/install_ubuntu_stable.sh --interface auto`.

The stable installer performs a clean deployment rather than layering over an old Python environment. It stops the old MON service, removes `/opt/campus-ops/venv`, creates a new managed virtual environment, installs the current repository without pip cache, verifies dependencies, installs/configures TShark capture permissions, purges former multi-sensor configuration/state, removes old sensor service files, installs the single MON service, waits for a real active capture session and runs `campus_ops.deployment_check`.

## Existing installation

```bash
cd ~/Campus-Cyber-Operations-Platform
git checkout monitor-v1
git fetch origin
git pull --ff-only origin monitor-v1
bash bootstrap.sh
```

Old MON files intentionally purged during migration include former managed-feed configuration, agent/response/tool/voice environment files, Zeek/Suricata/OpenCanary/Falco state directories and old MON sensor service definitions.

## Validate

```bash
sudo systemctl status campus-ops.service --no-pager
sudo /opt/campus-ops/venv/bin/python -m campus_ops.deployment_check
curl -s http://127.0.0.1:8765/api/v1/live/status | python3 -m json.tool
bash scripts/diagnose_runtime.sh
```

A healthy status should show:

```text
runtime_profile: stable-single-source
authoritative_packet_source: tshark
capture.state: ACTIVE
capture.backend: tshark
capture.process_pid: positive integer
network.interface == capture.interface
workers.network-discovery.state: HEALTHY
workers.capture.state: HEALTHY
```

`traffic_activity` may alternate between `PACKETS` and `QUIET`. That is normal and does not change capture from `ACTIVE` while TShark remains alive.

## Explicit interface

Automatic selection is the normal configuration. When a lab requires a fixed interface:

```bash
sudo bash scripts/install_ubuntu_stable.sh --interface eth0
```

The installer rejects an explicit interface that does not exist.

## Visibility boundary

MON sees packets delivered to its capture interface. A normal switched access port does not automatically receive all unicast traffic from other machines. Use authorized SPAN/mirror, TAP or gateway/bridge placement when broader passive visibility is required.
