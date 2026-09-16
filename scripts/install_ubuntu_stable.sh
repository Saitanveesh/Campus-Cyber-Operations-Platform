#!/usr/bin/env bash
set -euo pipefail

interface=auto
while (($#)); do
    case "$1" in
        --interface) interface="${2:?Missing interface}"; shift 2 ;;
        -h|--help)
            echo 'Usage: sudo bash scripts/install_ubuntu_stable.sh [--interface auto|NAME]'
            exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 64 ;;
    esac
done

[[ "$(id -u)" == 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
[[ "$interface" =~ ^[a-zA-Z0-9_.:@-]+$ ]] || { echo 'Invalid interface selector.' >&2; exit 64; }
source /etc/os-release
if [[ "${ID:-}" != ubuntu ]] || ! dpkg --compare-versions "${VERSION_ID:-0}" ge 22.04; then
    echo 'Ubuntu 22.04 or newer is required.' >&2
    exit 1
fi
if [[ "$(cat /proc/1/comm)" != systemd ]]; then
    echo 'A normal systemd Ubuntu host is required.' >&2
    exit 78
fi

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
report_dir=/var/lib/campus-ops/install
install -d -m 0755 "$report_dir" /opt/campus-ops /etc/campus-ops /etc/apt/keyrings
exec > >(tee -a "$report_dir/bootstrap.log") 2>&1
export DEBIAN_FRONTEND=noninteractive

echo '[campus-ops] Stable profile: one live packet source (TShark).'
apt-get update
apt-get install -y ca-certificates curl git python3-venv python3-pip iproute2 libcap2-bin jq

echo 'wireshark-common wireshark-common/install-setuid boolean true' | debconf-set-selections
apt-get install -y tshark

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

if [[ -d /opt/campus-ops/venv ]]; then
    rm -rf /opt/campus-ops/venv
fi
"$app_python" -m venv /opt/campus-ops/venv
app=/opt/campus-ops/venv/bin/python
"$app" -m pip install --upgrade pip
"$app" -m pip install --upgrade "$project_root"
"$app" -m pip check

getent group campus-ops >/dev/null || groupadd --system campus-ops
id campus-ops >/dev/null 2>&1 || useradd --system --gid campus-ops --home-dir /var/lib/campus-ops --shell /usr/sbin/nologin campus-ops
getent group wireshark >/dev/null || groupadd --system wireshark
usermod -a -G wireshark campus-ops

dumpcap_path="$(command -v dumpcap || true)"
if [[ -z "$dumpcap_path" ]]; then
    echo 'dumpcap helper missing from TShark installation.' >&2
    exit 1
fi
chown root:wireshark "$dumpcap_path"
chmod 0750 "$dumpcap_path"
setcap cap_net_raw,cap_net_admin=eip "$dumpcap_path"

capture_caps="$(getcap "$dumpcap_path" 2>/dev/null || true)"
if [[ "$capture_caps" != *cap_net_admin* || "$capture_caps" != *cap_net_raw* ]]; then
    echo "dumpcap capability verification failed: ${capture_caps:-none}" >&2
    exit 1
fi

# Verify the exact unprivileged service account can enumerate capture interfaces before
# enabling MON. This catches broken wireshark group membership/capability setups early.
if ! runuser -u campus-ops -- tshark -D >"$report_dir/tshark-interfaces.txt" 2>&1; then
    echo 'campus-ops cannot enumerate TShark capture interfaces.' >&2
    cat "$report_dir/tshark-interfaces.txt" >&2 || true
    exit 1
fi
if [[ ! -s "$report_dir/tshark-interfaces.txt" ]]; then
    echo 'TShark returned no capture interfaces for the campus-ops service account.' >&2
    exit 1
fi

if [[ "$interface" != auto ]] && ! ip link show dev "$interface" >/dev/null 2>&1; then
    echo "Requested interface does not exist: $interface" >&2
    exit 64
fi

install -d -m 0750 -o campus-ops -g campus-ops /var/lib/campus-ops
install -d -m 0750 -o root -g campus-ops /etc/campus-ops
cat > /etc/campus-ops/campus-ops.env <<EOF
CAMPUS_OPS_DATA_DIR=/var/lib/campus-ops
CAMPUS_OPS_NO_BROWSER=1
EOF
cat > /etc/campus-ops/sensors.env <<EOF
CAMPUS_OPS_INTERFACE=$interface
EOF
: > /etc/campus-ops/managed-feeds.env
chgrp campus-ops /etc/campus-ops/*.env
chmod 0640 /etc/campus-ops/*.env

install -m 0644 "$project_root/deploy/campus-ops.service" /etc/systemd/system/campus-ops.service

# Stable mode must not leave old parallel packet engines running from a previous install.
for unit in \
    campus-ops-sensor@zeek.service \
    campus-ops-sensor@suricata.service \
    campus-ops-sensor@opencanary.service \
    campus-ops-falco.service; do
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
done

"$app" - "$report_dir" <<'PY'
import json, time
from pathlib import Path
import sys
root = Path(sys.argv[1])
manifest = {
    'profile': 'stable-single-source',
    'completed_at': time.time(),
    'components': {
        'tshark': {'state': 'INSTALLED', 'detail': 'single authoritative live packet source'},
        'external-sensors': {'state': 'DISABLED', 'detail': 'Zeek/Suricata/Falco/OpenCanary not started in stable mode'},
    },
}
Path('/etc/campus-ops/deployment.json').write_text(json.dumps(manifest, indent=2) + '\n')
PY

systemctl daemon-reload
systemctl enable campus-ops.service
systemctl stop campus-ops.service >/dev/null 2>&1 || true
"$app" "$project_root/scripts/configure_ubuntu.py" --stop-previous-console || true
systemctl restart campus-ops.service

bash "$project_root/scripts/wait_for_console.sh" --url http://127.0.0.1:8765/api/v1/live/status --timeout 60
sleep 3
"$app" -m campus_ops.deployment_check

echo '[campus-ops] Stable setup complete.'
echo '[campus-ops] Console: http://127.0.0.1:8765'
