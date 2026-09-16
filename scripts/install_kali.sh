#!/usr/bin/env bash
set -euo pipefail

interface=auto
while (($#)); do
    case "$1" in
        --interface) interface="${2:?Missing interface}"; shift 2 ;;
        -h|--help)
            echo 'Usage: sudo bash scripts/install_kali.sh [--interface auto|NAME]'
            exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 64 ;;
    esac
done

[[ "$(id -u)" == 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
[[ "$interface" =~ ^[a-zA-Z0-9_.:@-]+$ ]] || { echo 'Invalid interface selector.' >&2; exit 64; }
source /etc/os-release
[[ "${ID:-}" == kali ]] || { echo 'This installer is for Kali Linux.' >&2; exit 1; }
[[ "$(cat /proc/1/comm)" == systemd ]] || { echo 'A normal systemd Kali host is required.' >&2; exit 78; }

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
report_dir=/var/lib/campus-ops/install
install -d -m 0755 "$report_dir" /opt/campus-ops /etc/campus-ops
exec > >(tee -a "$report_dir/bootstrap.log") 2>&1
export DEBIAN_FRONTEND=noninteractive

echo '[campus-ops] Installing Kali stable single-source monitor.'
apt-get update
apt-get install -y ca-certificates curl git python3 python3-venv python3-pip iproute2 libcap2-bin jq tshark

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

systemctl stop campus-ops.service >/dev/null 2>&1 || true
rm -rf /opt/campus-ops/venv
"$app_python" -m venv /opt/campus-ops/venv
app=/opt/campus-ops/venv/bin/python
"$app" -m pip install --upgrade pip setuptools wheel
"$app" -m pip install --upgrade --no-cache-dir "$project_root"
"$app" -m pip check

getent group campus-ops >/dev/null || groupadd --system campus-ops
id campus-ops >/dev/null 2>&1 || useradd --system --gid campus-ops --home-dir /var/lib/campus-ops --shell /usr/sbin/nologin campus-ops
getent group wireshark >/dev/null || groupadd --system wireshark
usermod -a -G wireshark campus-ops

dumpcap_path="$(command -v dumpcap || true)"
[[ -n "$dumpcap_path" ]] || { echo 'dumpcap helper missing from TShark installation.' >&2; exit 1; }
chown root:wireshark "$dumpcap_path"
chmod 0750 "$dumpcap_path"
setcap cap_net_raw,cap_net_admin=eip "$dumpcap_path"
capture_caps="$(getcap "$dumpcap_path" 2>/dev/null || true)"
[[ "$capture_caps" == *cap_net_admin* && "$capture_caps" == *cap_net_raw* ]] || {
    echo "dumpcap capability verification failed: ${capture_caps:-none}" >&2
    exit 1
}

runuser -u campus-ops -- tshark -D >"$report_dir/tshark-interfaces.txt" 2>&1 || {
    cat "$report_dir/tshark-interfaces.txt" >&2 || true
    exit 1
}
[[ -s "$report_dir/tshark-interfaces.txt" ]] || { echo 'TShark returned no capture interfaces.' >&2; exit 1; }
if [[ "$interface" != auto ]] && ! ip link show dev "$interface" >/dev/null 2>&1; then
    echo "Requested interface does not exist: $interface" >&2
    exit 64
fi

install -d -m 0750 -o campus-ops -g campus-ops /var/lib/campus-ops
install -d -m 0750 -o root -g campus-ops /etc/campus-ops
rm -f /etc/campus-ops/managed-feeds.env /etc/campus-ops/agents.env /etc/campus-ops/response.env /etc/campus-ops/tools.env /etc/campus-ops/voice.env
rm -rf /etc/campus-ops/sensors /var/lib/campus-ops/zeek /var/lib/campus-ops/suricata /var/lib/campus-ops/opencanary /var/lib/campus-ops/falco

cat > /etc/campus-ops/campus-ops.env <<EOF
CAMPUS_OPS_DATA_DIR=/var/lib/campus-ops
CAMPUS_OPS_NO_BROWSER=1
EOF
cat > /etc/campus-ops/sensors.env <<EOF
CAMPUS_OPS_INTERFACE=$interface
EOF
chgrp campus-ops /etc/campus-ops/campus-ops.env /etc/campus-ops/sensors.env
chmod 0640 /etc/campus-ops/campus-ops.env /etc/campus-ops/sensors.env

for unit in campus-ops-sensor@zeek.service campus-ops-sensor@suricata.service campus-ops-sensor@opencanary.service campus-ops-falco.service; do
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
done
rm -f /etc/systemd/system/campus-ops-sensor@.service /etc/systemd/system/campus-ops-falco.service
find /etc/systemd/system -maxdepth 2 -type l \( -name 'campus-ops-sensor@*.service' -o -name 'campus-ops-falco.service' \) -delete 2>/dev/null || true

install -m 0644 "$project_root/deploy/campus-ops.service" /etc/systemd/system/campus-ops.service
"$app" - <<'PY'
import json
import time
from pathlib import Path
Path('/etc/campus-ops/deployment.json').write_text(json.dumps({
    'profile': 'stable-single-source',
    'version': '0.5.0',
    'completed_at': time.time(),
    'components': {
        'tshark': {'state': 'INSTALLED', 'detail': 'single authoritative live packet source'},
        'legacy-sensors': {'state': 'REMOVED', 'detail': 'parallel sensor services/configuration purged'},
        'agent-control': {'state': 'REMOVED', 'detail': 'not part of stable passive runtime'},
    },
}, indent=2) + '\n')
PY

systemctl daemon-reload
systemctl enable campus-ops.service
systemctl restart campus-ops.service
bash "$project_root/scripts/wait_for_console.sh" --url http://127.0.0.1:8765/api/v1/live/status --timeout 60
sleep 3
"$app" -m campus_ops.deployment_check

echo '[campus-ops] Kali stable setup complete.'
echo '[campus-ops] Console: http://127.0.0.1:8765'
