#!/usr/bin/env bash
# Run after cloning: sudo bash scripts/install_ubuntu.sh
set -euo pipefail
profile=full
interface=auto
interface_args=()
plan=false
while (($#)); do
    case "$1" in
        --profile) profile="${2:?Missing profile}"; shift 2 ;;
        --interface) interface="${2:?Missing interface}"; interface_args=(--replace-interface); shift 2 ;;
        --plan) plan=true; shift ;;
        -h|--help)
            echo 'Usage: sudo bash scripts/install_ubuntu.sh [--profile full|core] [--interface auto|any|NAME] [--plan]'
            exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 64 ;;
    esac
done
[[ "$profile" == full || "$profile" == core ]] || { echo 'Profile must be full or core'; exit 64; }
[[ "$interface" =~ ^[a-zA-Z0-9_.:@-]+$ ]] || { echo 'Invalid interface selector'; exit 64; }
if $plan; then
    echo "Profile: $profile; interface: $interface"
    echo 'Core: Python 3.12+, TShark/dumpcap, Wireshark, tcpdump, network utilities, YARA, Zeek, Suricata.'
    [[ "$profile" == core ]] || echo 'Full adds: Falco (BTF kernel), OpenCanary, bcc, bpftrace, ClamAV, Sigma, Volatility 3, flow utilities.'
    echo 'Enabled services: console, Zeek, Suricata; full also OpenCanary (TCP 8081/8022) and compatible Falco.'
    echo 'Third-party packages: official Zeek/Falco repositories; uv managed Python on Ubuntu 22.04; PyPI application dependencies.'
    echo 'Commercial, cluster and external platforms need their own deployments. Active scanners are installed but never scheduled.'
    exit 0
fi
[[ "$(id -u)" == 0 ]] || { echo 'Run with sudo bash scripts/install_ubuntu.sh'; exit 1; }
source /etc/os-release
if [[ "${ID:-}" != ubuntu ]] || ! dpkg --compare-versions "${VERSION_ID:-0}" ge 22.04; then
    echo 'Ubuntu 22.04 or newer is required.' >&2; exit 1
fi
if [[ "$(cat /proc/1/comm)" != systemd ]]; then
    if [[ "$(uname -r)" == *[Mm]icrosoft* ]]; then
        python3 - <<'PY'
import configparser
from pathlib import Path
path = Path('/etc/wsl.conf')
config = configparser.ConfigParser()
config.read(path)
if not config.has_section('boot'):
    config.add_section('boot')
config.set('boot', 'systemd', 'true')
if path.exists():
    path.with_suffix('.conf.campus-backup').write_bytes(path.read_bytes())
with path.open('w') as stream:
    config.write(stream)
PY
        echo 'Enabled systemd in /etc/wsl.conf. Run wsl --shutdown in PowerShell, reopen Ubuntu, then rerun this installer.'
    else
        echo 'Persistent services require a systemd Ubuntu host (not this container).'
    fi
    exit 78
fi
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
report_dir=/var/lib/campus-ops/install
install -d -m 0755 "$report_dir" /opt/campus-ops /etc/apt/keyrings
exec > >(tee -a "$report_dir/bootstrap.log") 2>&1
failures=()
trap 'echo "Bootstrap stopped at line $LINENO. Log: /var/lib/campus-ops/install/bootstrap.log"' ERR
component() {
    local name="$1"
    shift
    rm -f "$report_dir/$name.ok" "$report_dir/$name.failed" "$report_dir/$name.blocked" "$report_dir/$name.external"
    if "$@"; then
        touch "$report_dir/$name.ok"
    else
        touch "$report_dir/$name.failed"
        failures+=("$name")
        echo "FAILED: $name; continuing independent components."
    fi
}
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl gnupg software-properties-common python3-venv python3-pip
add-apt-repository -y universe
echo 'wireshark-common wireshark-common/install-setuid boolean true' | debconf-set-selections
apt-get install -y tshark wireshark tcpdump iproute2 iw ethtool libcap2-bin net-tools \
    dnsutils iputils-ping traceroute jq openssl nmap arp-scan snmp lldpd yara logrotate

# Keep Ubuntu's system interpreter unchanged. The app needs >=3.12, including on 22.04.
app_python=/usr/bin/python3
if ! "$app_python" -c 'import sys; assert sys.version_info >= (3, 12)' 2>/dev/null; then
    uv_installer="$(mktemp)"
    curl --fail --location --retry 3 https://astral.sh/uv/install.sh -o "$uv_installer"
    UV_INSTALL_DIR=/opt/campus-ops/bin UV_NO_MODIFY_PATH=1 sh "$uv_installer"
    rm -f "$uv_installer"
    export UV_PYTHON_INSTALL_DIR=/opt/campus-ops/python
    /opt/campus-ops/bin/uv python install 3.12
    app_python="$(/opt/campus-ops/bin/uv python find --managed-python 3.12)"
fi
if [[ -x /opt/campus-ops/venv/bin/python ]] && ! /opt/campus-ops/venv/bin/python -c 'import sys; assert sys.version_info >= (3, 12)' 2>/dev/null; then
    mv /opt/campus-ops/venv "/opt/campus-ops/venv.backup.$(date +%s)"
fi
"$app_python" -m venv /opt/campus-ops/venv
app=/opt/campus-ops/venv/bin/python
"$app" -m pip install --upgrade pip
# Resolve the supported ranges for this interpreter, not another machine's freeze.
"$app" -m pip install --upgrade "$project_root"
"$app" -m pip check
"$app" -m pip freeze > "$report_dir/python-resolved.txt"
getent group campus-ops >/dev/null || groupadd --system campus-ops
for account in campus-ops campus-sensor; do
    id "$account" >/dev/null 2>&1 || useradd --system --gid campus-ops --home-dir /var/lib/campus-ops --shell /usr/sbin/nologin "$account"
done
getent group wireshark >/dev/null || groupadd --system wireshark
usermod -a -G wireshark campus-ops
dumpcap_path="$(command -v dumpcap)"
chown root:wireshark "$dumpcap_path"
chmod 0750 "$dumpcap_path"
setcap cap_net_raw,cap_net_admin=eip "$dumpcap_path"
install -d -m 0750 -o campus-ops -g campus-ops /var/lib/campus-ops
install -d -m 0750 -o root -g campus-ops /etc/campus-ops /etc/campus-ops/sensors
install -d -m 0750 -o campus-sensor -g campus-ops /var/log/campus-ops /run/campus-ops-sensors
for sensor in zeek suricata falco opencanary; do
    install -d -m 0750 -o campus-sensor -g campus-ops "/var/log/campus-ops/$sensor"
done

existing_suricata=false
systemctl is-active --quiet suricata.service && existing_suricata=true
component suricata apt-get install -y suricata suricata-update
if $existing_suricata; then
    mv "$report_dir/suricata.ok" "$report_dir/suricata.external" 2>/dev/null || true
    echo 'Preserving existing Suricata service; its feed must be configured in campus-ops.env.'
elif [[ -f "$report_dir/suricata.ok" ]]; then
    systemctl disable --now suricata.service || true
    component suricata-rules suricata-update --no-reload
fi
zeek_repo="https://download.opensuse.org/repositories/security:/zeek/xUbuntu_${VERSION_ID}"
# Functions used by component explicitly propagate errors (errexit is disabled inside if).
install_zeek() {
    curl -fsSL --retry 3 "$zeek_repo/Release.key" -o "$report_dir/zeek.asc" &&
    gpg --batch --yes --dearmor -o /etc/apt/keyrings/campus-zeek.gpg "$report_dir/zeek.asc" &&
    echo "deb [signed-by=/etc/apt/keyrings/campus-zeek.gpg] $zeek_repo/ /" > /etc/apt/sources.list.d/campus-zeek.list &&
    apt-get update && apt-get install -y zeek-8.0
}
component zeek install_zeek
canary_args=()
if [[ "$profile" == full ]]; then
    for package in clamav bpfcc-tools bpftrace nfdump pmacct softflowd; do
        component "$package" apt-get install -y "$package"
    done
    "$app_python" -m venv /opt/campus-ops/analysis
    component analysis-tools /opt/campus-ops/analysis/bin/python -m pip install --upgrade sigma-cli volatility3
    "$app_python" -m venv /opt/campus-ops/opencanary
    component opencanary /opt/campus-ops/opencanary/bin/python -m pip install --upgrade opencanary
    if [[ -f "$report_dir/opencanary.ok" ]]; then
        /opt/campus-ops/opencanary/bin/python - <<'PY' > "$report_dir/opencanary-defaults.json"
from importlib.resources import files
print(files('opencanary').joinpath('data/settings.json').read_text())
PY
        canary_args=(--canary-defaults "$report_dir/opencanary-defaults.json")
    fi
    if systemctl is-active --quiet falco.service || systemctl is-active --quiet falco-modern-bpf.service; then
        rm -f "$report_dir/falco.ok" "$report_dir/falco.failed" "$report_dir/falco.blocked"
        touch "$report_dir/falco.external"
        echo 'Preserving existing Falco service; configure its export in campus-ops.env.'
    elif [[ -r /sys/kernel/btf/vmlinux ]]; then
        install_falco() {
            curl -fsSL --retry 3 https://falco.org/repo/falcosecurity-packages.asc -o "$report_dir/falco.asc" &&
            gpg --batch --yes --dearmor -o /etc/apt/keyrings/campus-falco.gpg "$report_dir/falco.asc" &&
            echo 'deb [signed-by=/etc/apt/keyrings/campus-falco.gpg] https://download.falco.org/packages/deb stable main' > /etc/apt/sources.list.d/campus-falco.list &&
            apt-get update && env FALCO_FRONTEND=noninteractive FALCO_DRIVER_CHOICE=none FALCOCTL_ENABLED=no apt-get install -y falco
        }
        component falco install_falco
    else
        rm -f "$report_dir/falco.ok" "$report_dir/falco.failed" "$report_dir/falco.external"
        echo 'Kernel BTF is unavailable; Falco modern eBPF cannot start on this kernel.' > "$report_dir/falco.blocked"
    fi
fi
"$app" "$project_root/scripts/configure_ubuntu.py" --interface "$interface" "${interface_args[@]}" "${canary_args[@]}"
if [[ ! -f /etc/campus-ops/risk-policy.json ]]; then
    install -m 0640 "$project_root/config/risk-policy.json" /etc/campus-ops/risk-policy.json
fi
chgrp -R campus-ops /etc/campus-ops
chmod 0640 /etc/campus-ops/*.env /etc/campus-ops/sensors/*
for unit in campus-ops.service campus-ops-sensor@.service campus-ops-falco.service; do
    install -m 0644 "$project_root/deploy/$unit" "/etc/systemd/system/$unit"
done
install -m 0644 "$project_root/deploy/campus-ops-tmpfiles.conf" /etc/tmpfiles.d/campus-ops.conf
install -m 0644 "$project_root/deploy/campus-ops-logrotate" /etc/logrotate.d/campus-ops
systemd-tmpfiles --create /etc/tmpfiles.d/campus-ops.conf
systemctl daemon-reload
for sensor in zeek suricata opencanary; do
    if [[ -f "$report_dir/$sensor.ok" ]]; then
        systemctl enable "campus-ops-sensor@$sensor.service"
        component "$sensor-service" systemctl restart "campus-ops-sensor@$sensor.service"
    fi
done
if [[ -f "$report_dir/falco.ok" ]]; then
    systemctl enable campus-ops-falco.service
    component falco-service systemctl restart campus-ops-falco.service
fi
"$app" - "$report_dir" "$profile" <<'PY'
import json, sys, time
from pathlib import Path
directory = Path(sys.argv[1])
states = {'ok': 'INSTALLED', 'failed': 'FAILED', 'blocked': 'BLOCKED', 'external': 'EXTERNAL_SERVICE'}
components = {p.stem: {'state': states[p.suffix[1:]], 'detail': p.read_text()[:500]}
              for p in directory.iterdir() if p.suffix[1:] in states}
manifest = {'profile': sys.argv[2], 'completed_at': time.time(), 'components': components}
Path('/etc/campus-ops/deployment.json').write_text(json.dumps(manifest, indent=2) + '\n')
PY
systemctl enable campus-ops.service
# Stop the old managed service, then migrate a verified manual instance if present.
systemctl stop campus-ops.service
"$app" "$project_root/scripts/configure_ubuntu.py" --stop-previous-console
systemctl restart campus-ops.service
for ((attempt=0; attempt<20; attempt++)); do
    if curl -fsS http://127.0.0.1:8765/api/v1/system/deployment >/dev/null; then break; fi
    sleep 1
done
# Allow child processes to finish initialization before checking their heartbeats.
sleep 6
if ! "$app" -m campus_ops.deployment_check; then
    failures+=(health-check)
fi
echo 'Console: http://127.0.0.1:8765 ; health: sudo /opt/campus-ops/venv/bin/python -m campus_ops.deployment_check'
if ((${#failures[@]})); then
    echo "Partial setup: ${failures[*]}. Details: $report_dir/bootstrap.log"
    exit 2
fi
echo 'Setup completed. Services start automatically on boot. Refresh the console.'
