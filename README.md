# Campus Cyber Operations Platform — MON Stable 0.5.0

`monitor-v1` is the field-stable passive monitoring profile. The repository has been reduced to one packet acquisition path and one runtime model so old sensor, agent, response and enterprise experiments cannot be loaded accidentally.

## Runtime contract

MON Stable 0.5.0 has one authoritative packet source: **TShark**. Automatic interface selection chooses one eligible active interface and uses confirmation/hysteresis before changing it. The live session, Assets, Traffic, Topology, Path Space and Security views are all derived from that same packet stream.

Local Assets require repeated local source-frame evidence with a valid unicast source MAC. A remote address seen in a packet may appear as an observed traffic peer, but it is not promoted to a local asset.

The stable runtime does not mount agent control, remote shell, quarantine/isolation, active network probing, Zeek, Suricata, Falco, OpenCanary, NetFlow, SNMP, syslog, voice, malware scanning, endpoint telemetry or the former enterprise/admin console stack.

## Console

Primary navigation:

`Overview · Network · Topology · Path Space · Assets · Traffic · Security · Investigation · Forensics · System`

Investigation and Forensics are local authenticated passive-evidence workspaces. There is no Admin panel and no active-response control surface in the stable application.

## Install

Ubuntu 22.04+:

```bash
sudo apt update
sudo apt install -y git curl ca-certificates
git clone --branch monitor-v1 --single-branch https://github.com/Saitanveesh/Campus-Cyber-Operations-Platform.git
cd Campus-Cyber-Operations-Platform
bash bootstrap.sh
```

Kali Linux uses the same stable single-source runtime:

```bash
git clone --branch monitor-v1 --single-branch https://github.com/Saitanveesh/Campus-Cyber-Operations-Platform.git
cd Campus-Cyber-Operations-Platform
bash bootstrap.sh
```

On every install/upgrade, MON recreates `/opt/campus-ops/venv` instead of reusing the old Python environment. The installer also removes stale multi-sensor configuration and disables/removes old MON sensor service units before starting the current service.

Console: `http://127.0.0.1:8765`

## Update an existing machine

```bash
cd ~/Campus-Cyber-Operations-Platform
git checkout monitor-v1
git fetch origin
git pull --ff-only origin monitor-v1
bash bootstrap.sh
```

## Capture state

`ACTIVE` means the managed TShark process is alive and bound to the selected interface. Quiet traffic keeps capture `ACTIVE` and changes only `traffic_activity` to `QUIET`. `WAITING` means no confirmed interface/session exists yet. `UNAVAILABLE` means TShark cannot be resolved. `ERROR` means the actual managed TShark process failed.

This prevents normal quiet periods from appearing as capture/link failures.

## Verify

```bash
sudo systemctl status campus-ops.service --no-pager
sudo /opt/campus-ops/venv/bin/python -m campus_ops.deployment_check
curl -s http://127.0.0.1:8765/api/v1/live/status | python3 -m json.tool
curl -s http://127.0.0.1:8765/api/v1/system/version | python3 -m json.tool
```

A ready deployment requires an active session, selected interface, healthy network-discovery and capture workers, a live TShark PID, matching network/capture interface, and the required Linux capture capabilities.

## Development

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/ruff check src tests
.venv/bin/pytest -q
CAMPUS_OPS_NO_BROWSER=1 .venv/bin/python -m campus_ops
```

## Visibility boundary

MON can report only traffic visible to its capture interface. On a switched network, a normal access port normally does not receive all other hosts' unicast traffic. Wider passive visibility requires legitimate sensor placement such as a SPAN/mirror port, TAP or gateway/bridge position. MON does not invent physical switch/router hops that it cannot observe.
