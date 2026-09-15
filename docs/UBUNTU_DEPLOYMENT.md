# Ubuntu deployment

Supports Ubuntu 22.04 and 24.04 with systemd. Newer Ubuntu releases are attempted, but vendor repositories may not publish packages for them yet. Package or service failures are reported; they are never hidden as successful integration.

## Install or upgrade

For a new checkout:

```bash
git clone --branch monitor-v1 --single-branch https://github.com/Saitanveesh/Campus-Cyber-Operations-Platform.git
cd Campus-Cyber-Operations-Platform
sudo bash scripts/install_ubuntu.sh --interface any
```

For an existing checkout:

```bash
cd ~/Campus-Cyber-Operations-Platform
git pull --ff-only origin monitor-v1
sudo bash scripts/install_ubuntu.sh --interface any
```

Open http://127.0.0.1:8765 and refresh the Tool Hub. Git itself only downloads source; the explicit installer runs the privileged setup. It installs a separate Python 3.12 runtime on Ubuntu 22.04, creates the application environment under `/opt/campus-ops`, and enables the console and supported sensors at boot. It can replace a verified manual `python -m campus_ops` listener belonging to the invoking user with the managed service. An unrelated listener on port 8765 causes a clear error.

Use `bash scripts/install_ubuntu.sh --plan` to print the package/service plan without changes. Setup can be rerun after a failed download. Existing operator configuration is preserved, except for migration of the two old default export paths and an explicitly supplied `--interface` choice. No UI source or colour has changed.

## Profiles

| Profile | Installed packages and services |
|---|---|
| `core` | Python application, TShark/dumpcap, Wireshark, tcpdump, iproute2/iw/ethtool, DNS and network utilities, Nmap/arp-scan, SNMP/LLDP CLI, YARA; Zeek and Suricata with configured logs and supervised services |
| `full` (default) | Core plus Falco when kernel BTF exists, OpenCanary HTTP/SSH services, bcc and bpftrace tools, ClamAV CLI, flow utilities, isolated Sigma and Volatility 3 environment |

The full profile opens decoy HTTP on TCP 8081 and SSH on TCP 8022, bound to local IPv4 interfaces. Their interactions feed the evidence pipeline. Change `/etc/campus-ops/sensors/opencanary.conf` to adjust listening addresses and ports. No firewall rule is added. Existing active vendor Suricata/Falco services are preserved and reported as `EXTERNAL_SERVICE`, requiring their actual export paths.

Installed analysis and discovery CLIs are available on demand. Nmap/arp-scan are not automatically scheduled. The licensed products, cluster components, separate servers and adversary-emulation frameworks listed in [integration status](TOOL_INTEGRATIONS.md) require their own deployment; the installer does not pretend to install or operate them.

## Interfaces and WSL

- `--interface auto`: follows an eligible routed interface, re-evaluating live link and route state before a switch. Ethernet, Wi-Fi, USB and tunnel names are supported. Disconnected links are dropped immediately; switches use two confirmations.
- `--interface any`: captures on the Linux libpcap `any` device, including interfaces that appear later. This includes loopback and can observe duplicate traffic across bridges/tunnels. It does not turn Wi-Fi into monitor mode.
- `--interface wlp2s0` (or another exact name): selects that Linux device, including an unnumbered SPAN/TAP or VPN interface. If absent or down, capture waits instead of silently moving elsewhere.

The console and managed network sensors use the same election logic. `ip -br address` lists Linux-visible device names. Interface changes restart packet sessions and rebind Zeek/Suricata; Linux capture uses device names rather than cached numeric indexes.

WSL can only expose devices and traffic visible inside its Linux environment. A virtual `eth0` may carry the laptop's Wi-Fi traffic; the host Wi-Fi radio and SSID may not be accessible through `iw`. This software cannot infer packets from the rest of a switched campus network. Use native Ubuntu or a configured mirror/TAP for that scope.

If WSL has no systemd, setup preserves its configuration, enables `[boot] systemd=true` in `/etc/wsl.conf`, and exits with instructions to run `wsl --shutdown` from PowerShell. Reopen Ubuntu and rerun setup. This one restart is necessary before persistent Linux services can work. Falco is reported blocked when BTF is absent, and actual eBPF startup can still fail on an incompatible kernel.

## Health and maintenance

```bash
sudo /opt/campus-ops/venv/bin/python -m campus_ops.deployment_check
sudo systemctl status campus-ops 'campus-ops-sensor@*' campus-ops-falco --no-pager
sudo journalctl -u campus-ops -u 'campus-ops-sensor@*' -u campus-ops-falco -n 100 --no-pager
```

Read-only status: `/api/v1/system/deployment`, `/api/v1/system/telemetry-fabric`, `/api/v1/system/operations-fabric`. The Tool Hub retains its existing layout and shows new rows plus service/feed details.

- `READY_NATIVE` / `READY_WSL`: executable found, not an ingestion claim.
- `READY_LISTENING`: managed sensor process is alive, awaiting recent records.
- `READY_RECEIVING`: records accepted within the last minute.
- `BLOCKED`, `FAILED`, `NOT_RUNNING`, `WAITING_INTERFACE`: actual runtime or installation limitation.
- `REQUIRES_DEPLOYMENT` / `NOT_APPLICABLE`: external prerequisite or Windows-only tool.

Quiet Falco/OpenCanary feeds need not have alerts. The health checker verifies supervised processes and capture access as the `campus-ops` account; it does not invent traffic or detections. Installer exit 2 means partial setup: inspect the printed problems and `/var/lib/campus-ops/install/bootstrap.log`. Exit 78 means systemd needs activation. Do not interpret either as a completed full installation.

The app runs as `campus-ops`; packet capture uses dumpcap's file capabilities. Zeek/Suricata/OpenCanary run as `campus-sensor`. Falco's dedicated system service runs with privileges needed for modern eBPF. Python packages and configuration remain root-owned. Logs are readable by the application group; bounded rotation lives in `/etc/logrotate.d/campus-ops`. Source outputs and diagnostic logs are under `/var/log/campus-ops`. Runtime heartbeats expire after 15 seconds. Supervisors restart children with backoff and systemd restarts failed supervisors.

Manual sensor configuration goes in `/etc/campus-ops/sensors/`. Generated feed paths are in `managed-feeds.env`; operator overrides belong in `campus-ops.env` and take precedence. Change interfaces with the installer flag or `sensors.env`, then restart the console and sensor units. Paths for externally deployed Tetragon, Hubble and Wazuh can be configured using `config/ubuntu.env.example`. Grant read/traverse access through rotated files and parent directories. Readers skip existing content at attachment/session changes to keep historical events out of live evidence.

Default autonomy is observe. Optional investigate mode permits bounded snapshots of unambiguous online enrolled endpoints. Linux automatic containment remains disabled. See [risk register](RISK_REGISTER.md).

## Validation and package sources

Application tests run on Python 3.12 and 3.13. The bootstrap CI runs the full installer on Ubuntu 22.04 and 24.04, verifies capture permissions and sensor restarts, and keeps diagnostic artifacts. These checks do not establish physical laptop driver support or campus throughput.

The installer resolves application dependency ranges for its managed interpreter, runs `pip check`, and saves the resulting versions in `/var/lib/campus-ops/install/python-resolved.txt`. CI also tests `requirements.lock` independently. System Python is not downgraded or replaced.

Primary installation references: [Zeek native packages](https://docs.zeek.org/en/current/install.html), [Falco host packages](https://falco.org/docs/setup/packages/), [Suricata quickstart](https://docs.suricata.io/en/latest/quickstart.html), [OpenCanary](https://github.com/thinkst/opencanary), [uv installation](https://docs.astral.sh/uv/getting-started/installation/). Zeek uses the 8.0 LTS package line; vendor APT keys are scoped to their repositories. Download failures remain explicit installation failures.
