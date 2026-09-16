# Campus Cyber Operations Platform — Stable Monitor 0.4.2

`monitor-v1` is the stabilized monitoring runtime for authorized lab and campus networks.

## Runtime contract

Stable MON is built around one acquisition chain:

1. **One authoritative live packet source:** TShark.
2. **One selected monitoring interface:** automatic selection prefers the active routed network and uses confirmation/hysteresis before changing it.
3. **One live monitoring session:** short interface observations do not immediately destroy the session.
4. **Evidence-backed state:** local assets require repeated local source-frame evidence with a valid unicast MAC address.
5. **Derived views, not extra capture engines:** Topology, Path Space, Assets, Traffic and Security are computed from the same TShark packet stream.

Zeek, Suricata, Falco, OpenCanary, SNMP, syslog, flow-export collectors and the older experimental enterprise consoles are **not started by the stable Ubuntu runtime**.

## Stable console

The primary navigation exposes:

- Overview
- Network
- Topology
- Path Space
- Assets
- Traffic
- Security
- Investigation
- Forensics
- System

There is no separate **Admin** panel in stable mode. **Investigation** and **Forensics** are first-class protected workspaces in the normal navigation. They require a local-console operator sign-in and expose passive target/evidence functions only. The stable operator API does not mount active probe, remote-console or containment endpoints from the legacy admin console.

## Fresh Ubuntu install

Use Ubuntu 22.04 or newer with systemd and an active network connection. For the normal direct-LAN deployment, leave interface selection on `auto`.

```bash
sudo apt update
sudo apt install -y git curl ca-certificates
git clone --branch monitor-v1 --single-branch https://github.com/Saitanveesh/Campus-Cyber-Operations-Platform.git
cd Campus-Cyber-Operations-Platform
bash bootstrap.sh
```

`bootstrap.sh` selects the stable Ubuntu installer automatically. It installs the managed Python runtime and TShark, configures Wireshark/dumpcap capture permissions, disables old parallel managed sensors if they exist, installs the systemd service, waits for the real MON capture runtime to become ready, and runs the post-install deployment check.

Console: `http://127.0.0.1:8765`

## Existing clone

```bash
cd ~/Campus-Cyber-Operations-Platform
git checkout monitor-v1
git pull --ff-only origin monitor-v1
bash bootstrap.sh
```

## Interface selection and session stability

The interface selector defaults to `auto`. MON detects the active network interface and requires repeated confirmation before switching interfaces or accepting a material network-identity change. Stable mode also requires multiple consecutive missing/down observations before declaring the network unavailable.

This prevents a single NetworkManager/DHCP/routing observation from resetting the session or restarting TShark.

An explicitly selected interface can still be configured when a lab requires it, but `auto` is the normal deployment setting.

## Capture-state semantics

Capture state is based on the actual TShark process, not on packet arrival rate:

- `ACTIVE` — the managed TShark process is alive and bound to the selected interface.
- `WAITING` — there is not yet a confirmed interface/session to bind.
- `UNAVAILABLE` — TShark is not installed/resolvable.
- `ERROR` — the managed TShark process exited, could not start, or its output stream failed.

When the wire is quiet, capture remains `ACTIVE` and `traffic_activity` becomes `QUIET`. Packet silence does **not** trigger an interface rebind, session reset or false link failure.

## Asset truth model

The **Assets** page is local inventory, not a list of every IP appearing in packet headers.

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

A deployment is ready only when the managed service, network-discovery worker, capture worker, selected interface and the actual managed TShark PID agree. The version endpoint records the deployed branch, commit and stable runtime profile.

## Development

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/ruff check src tests
.venv/bin/pytest -q
CAMPUS_OPS_NO_BROWSER=1 .venv/bin/python -m campus_ops
```

## Visibility scope

MON reports what reaches its capture interface. A normal switched access port does not automatically receive every unicast conversation on the LAN. Monitoring other hosts' traffic therefore depends on sensor placement such as a SPAN/mirror port, TAP, bridge/gateway position, or another legitimate telemetry source.

The stable console does not infer physical switch/router hops unless infrastructure evidence supports them, and it does not treat every observed remote IP as a local device.
