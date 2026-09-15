#!/usr/bin/env bash
# Kali Linux deployment path for monitor-v1. Run through bootstrap.sh or with sudo.
set -euo pipefail

profile=full
interface=auto
while (($#)); do
    case "$1" in
        --profile) profile="${2:?Missing profile}"; shift 2 ;;
        --interface) interface="${2:?Missing interface}"; shift 2 ;;
        --plan) plan=true; shift ;;
        -h|--help)
            echo 'Usage: sudo bash scripts/install_kali.sh [--profile full|core] [--interface auto|NAME] [--plan]'
            exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 64 ;;
    esac
done
plan=${plan:-false}
[[ "$profile" == full || "$profile" == core ]] || { echo 'Profile must be full or core'; exit 64; }
[[ "$interface" =~ ^[a-zA-Z0-9_.:@-]+$ ]] || { echo 'Invalid interface selector'; exit 64; }

if $plan; then
    echo "Platform: Kali Linux; profile: $profile; interface: $interface"
    echo 'Core: Python 3.12+, TShark/dumpcap, Wireshark, tcpdump, iproute2/iw, Nmap, YARA, Zeek and Suricata.'
    [[ "$profile" == core ]] || echo 'Full: OpenCanary, ClamAV, bpftrace, BCC and flow utilities where Kali packages support them.'
    exit 0
fi

[[ "$(id -u)" == 0 ]] || { echo 'Run with sudo bash scripts/install_kali.sh'; exit 1; }
# shellcheck disable=SC1091
source /etc/os-release
[[ "${ID:-}" == kali ]] || { echo "Kali Linux is required by this installer; detected ${PRETTY_NAME:-unknown}." >&2; exit 1; }
[[ "$(cat /proc/1/comm)" == systemd ]] || { echo 'A systemd Kali host is required.' >&2; exit 78; }

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
report_dir=/var/lib/campus-ops/install
install -d -m 0755 "$report_dir" /opt/campus-ops /etc/apt/keyrings
exec > >(tee -a "$report_dir/bootstrap.log") 2>&1
trap 'echo "Kali bootstrap stopped at line $LINENO. Log: /var/lib/campus-ops/install/bootstrap.log"' ERR

component() {
    local name="$1"; shift
    rm -f "$report_dir/$name.ok" "$report_dir/$name.failed" "$report_dir/$name.blocked" "$report_dir/$name.external"
    if "$@"; then
        touch "$report_dir/$name.ok"
    else
        touch "$report_dir/$name.failed"
        echo "FAILED: $name"
        return 1
    fi
}
optional_component() {
    local name="$1"; shift
    rm -f "$report_dir/$name.ok" "$report_dir/$name.failed" "$report_dir/$name.blocked" "$report_dir/$name.external"
    if "$@"; then
        touch "$report_dir/$name.ok"
    else
        echo "Optional component unavailable on this Kali image: $name" > "$report_dir/$name.blocked"
        return 0
    fi
}

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl git gnupg python3 python3-venv python3-pip python3-dev build-essential

echo 'wireshark-common wireshark-common/install-setuid boolean true' | debconf-set-selections
apt-get install -y tshark wireshark tcpdump iproute2 iw ethtool libcap2-bin net-tools \
    dnsutils iputils-ping traceroute jq openssl nmap arp-scan snmp lldpd yara logrotate \
    suricata suricata-update

# Zeek is in Kali's rolling repositories. Keep /opt/zeek/bin compatibility for the sensor runner.
component zeek apt-get install -y zeek
zeek_path="$(command -v zeek || true)"
if [[ -z "$zeek_path" ]]; then
    zeek_path="$(find /usr -type f -name zeek -perm -111 2>/dev/null | head -n1 || true)"
fi
if [[ -n "$zeek_path" ]]; then
    install -d -m 0755 /opt/zeek/bin
    ln -sfn "$zeek_path" /opt/zeek/bin/zeek
else
    echo 'Zeek package installed but executable was not found.' >&2
    touch "$report_dir/zeek.failed"
    exit 1
fi
component suricata true
component suricata-rules suricata-update --no-reload

if [[ "$profile" == full ]]; then
    optional_component clamav apt-get install -y clamav
    optional_component bpftrace apt-get install -y bpftrace
    optional_component bcc apt-get install -y bpfcc-tools
    optional_component nfdump apt-get install -y nfdump
    optional_component pmacct apt-get install -y pmacct
    optional_component softflowd apt-get install -y softflowd
fi

# Use the system Python when it is new enough; otherwise install a managed 3.12 runtime.
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
rm -rf /opt/campus-ops/venv.new
"$app_python" -m venv /opt/campus-ops/venv.new
/opt/campus-ops/venv.new/bin/python -m pip install --upgrade pip
/opt/campus-ops/venv.new/bin/python -m pip install --upgrade "$project_root"
/opt/campus-ops/venv.new/bin/python -m pip check
if [[ -d /opt/campus-ops/venv ]]; then
    rm -rf /opt/campus-ops/venv.previous
    mv /opt/campus-ops/venv /opt/campus-ops/venv.previous
fi
mv /opt/campus-ops/venv.new /opt/campus-ops/venv
app=/opt/campus-ops/venv/bin/python
"$app" -m pip freeze > "$report_dir/python-resolved.txt"

getent group campus-ops >/dev/null || groupadd --system campus-ops
for account in campus-ops campus-sensor; do
    id "$account" >/dev/null 2>&1 || useradd --system --gid campus-ops --home-dir /var/lib/campus-ops --shell /usr/sbin/nologin "$account"
done
getent group wireshark >/dev/null || groupadd --system wireshark
usermod -a -G wireshark campus-ops
if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != root ]] && id "$SUDO_USER" >/dev/null 2>&1; then
    usermod -a -G wireshark "$SUDO_USER"
fi

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

canary_args=()
if [[ "$profile" == full ]]; then
    "$app_python" -m venv /opt/campus-ops/opencanary
    if /opt/campus-ops/opencanary/bin/python -m pip install --upgrade opencanary; then
        touch "$report_dir/opencanary.ok"
        /opt/campus-ops/opencanary/bin/python - <<'PY' > "$report_dir/opencanary-defaults.json"
from importlib.resources import files
print(files('opencanary').joinpath('data/settings.json').read_text())
PY
        canary_args=(--canary-defaults "$report_dir/opencanary-defaults.json")
    else
        echo 'OpenCanary pip installation unavailable' > "$report_dir/opencanary.blocked"
    fi
    # Falco support is kernel/repository dependent on Kali; do not misreport it as operational.
    if command -v falco >/dev/null 2>&1 && [[ -r /sys/kernel/btf/vmlinux ]]; then
        touch "$report_dir/falco.external"
    else
        echo 'Falco not enabled: requires a compatible installed Falco plus kernel BTF.' > "$report_dir/falco.blocked"
    fi
fi

"$app" "$project_root/scripts/configure_ubuntu.py" --interface "$interface" --replace-interface "${canary_args[@]}"
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
        systemctl restart "campus-ops-sensor@$sensor.service"
    fi
done

"$app" - "$report_dir" "$profile" <<'PY'
import json, sys, time
from pathlib import Path
directory = Path(sys.argv[1])
states = {'ok': 'INSTALLED', 'failed': 'FAILED', 'blocked': 'BLOCKED', 'external': 'EXTERNAL_SERVICE'}
components = {p.stem: {'state': states[p.suffix[1:]], 'detail': p.read_text()[:500]}
              for p in directory.iterdir() if p.suffix[1:] in states}
manifest = {'profile': 'kali-' + sys.argv[2], 'completed_at': time.time(), 'components': components}
Path('/etc/campus-ops/deployment.json').write_text(json.dumps(manifest, indent=2) + '\n')
PY

systemctl enable campus-ops.service
systemctl stop campus-ops.service 2>/dev/null || true
"$app" "$project_root/scripts/configure_ubuntu.py" --stop-previous-console
systemctl restart campus-ops.service

if ! bash "$project_root/scripts/wait_for_console.sh" --url http://127.0.0.1:8765/api/v1/system/deployment --timeout 60; then
    echo 'Campus Ops console did not become ready; service diagnostics were printed above.' >&2
    exit 2
fi
sleep 4
"$app" -m campus_ops.deployment_check || true

echo 'Kali deployment complete.'
echo 'Console: http://127.0.0.1:8765'
echo 'If you run TShark manually, start a new login session so your wireshark group membership is refreshed.'
