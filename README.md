# Campus Cyber Operations Platform — Stable Monitor 0.4

`monitor-v1` now defaults to a deliberately reduced monitoring runtime for authorized lab and campus networks.

## Why the runtime was simplified

Field testing exposed instability from running several independent packet/sensor pipelines at the same time. It also made the console overstate what was known about observed IP addresses. Stable 0.4 therefore follows three rules:

1. **One authoritative live packet source:** TShark.
2. **Local assets require evidence:** an address is not promoted to the Assets inventory until it is observed repeatedly as a local source with a valid unicast MAC address.
3. **Fewer consoles:** the production UI exposes only Overview, Network, Assets, Traffic, Security and System.

Zeek, Suricata, Falco, OpenCanary, SNMP, syslog, flow-export collectors, forensic capture and experimental enterprise consoles remain source-code experiments or legacy integrations. They are **not started by the stable Ubuntu runtime**.

## Fresh Ubuntu install

Use Ubuntu 22.04 or newer with systemd and an active Ethernet/Wi-Fi connection.

```bash
sudo apt update
sudo apt install -y git curl ca-certificates
git clone --branch monitor-v1 --single-branch https://github.com/Saitanveesh/Campus-Cyber-Operations-Platform.git
cd Campus-Cyber-Operations-Platform
bash bootstrap.sh
```

`bootstrap.sh` selects the stable Ubuntu installer automatically. It installs the managed Python runtime and TShark, configures Wireshark's capture helper permissions, disables old parallel managed sensors if they exist, installs the systemd service, waits for the HTTP console and runs the post-install check.

Console: `http://127.0.0.1:8765`

## Existing clone

```bash
cd ~/Campus-Cyber-Operations-Platform
git checkout monitor-v1
git pull --ff-only origin monitor-v1
bash bootstrap.sh
```

## Stable runtime behavior

The interface selector defaults to `auto`. The platform chooses an active routed physical interface and uses hysteresis before declaring a link unavailable, so a single transient poll does not destroy the session.

The capture state has intentionally simple semantics:

- `ACTIVE` — TShark is receiving packets.
- `LINK_UP_IDLE` — capture process is healthy, but no packet arrived during the last interval.
- `WAITING` — no confirmed active interface/session yet.
- `ERROR` — TShark actually exited or could not open the interface.

`LINK_UP_IDLE` is not an uplink failure.

## Asset truth model

The **Assets** page is local inventory, not a list of every IP seen in packet headers.

An asset is admitted only when:

- its address belongs to the selected local network, gateway or sensor identity;
- the packet has a valid unicast source MAC; and
- the same IP/MAC pair is observed in at least two source frames.

Public Internet servers and off-subnet peers can appear in **Traffic** only when they were actually observed communicating with the local network. They are not promoted to local assets.

## Verification

```bash
sudo systemctl status campus-ops.service --no-pager
sudo /opt/campus-ops/venv/bin/python -m campus_ops.deployment_check
curl -s http://127.0.0.1:8765/api/v1/live/status | python3 -m json.tool
curl -s http://127.0.0.1:8765/api/v1/system/version | python3 -m json.tool
```

The version endpoint records the deployed branch, commit and stable runtime profile.

## Development

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/ruff check src tests
.venv/bin/pytest -q
CAMPUS_OPS_NO_BROWSER=1 .venv/bin/python -m campus_ops
```

## Scope

This is a passive monitoring console. It does not infer physical network paths, does not claim that every remote IP is a local device, and stable mode does not start automatic containment or multiple competing packet engines.
