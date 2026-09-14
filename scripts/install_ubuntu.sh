#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" != 0 ]]; then
    echo "Run with sudo bash scripts/install_ubuntu.sh" >&2
    exit 1
fi
source /etc/os-release
if [[ "${ID:-}" != ubuntu ]] || ! dpkg --compare-versions "${VERSION_ID:-0}" ge 24.04; then
    echo "Ubuntu 24.04 or newer is required." >&2
    exit 1
fi
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
export DEBIAN_FRONTEND=noninteractive
echo 'wireshark-common wireshark-common/install-setuid boolean true' | debconf-set-selections
apt-get update
apt-get install -y python3-venv python3-pip iproute2 tshark libcap2-bin
python3 -c 'import sys; assert sys.version_info >= (3, 12), "Python 3.12+ required"'
getent group campus-ops >/dev/null || groupadd --system campus-ops
id campus-ops >/dev/null 2>&1 || useradd --system --gid campus-ops --home-dir /var/lib/campus-ops --shell /usr/sbin/nologin campus-ops
getent group wireshark >/dev/null || groupadd --system wireshark
usermod -a -G wireshark campus-ops
dumpcap_path="$(command -v dumpcap)"
chown root:wireshark "$dumpcap_path"
chmod 0750 "$dumpcap_path"
setcap cap_net_raw,cap_net_admin=eip "$dumpcap_path"
install -d -m 0750 -o campus-ops -g campus-ops /var/lib/campus-ops
install -d -m 0755 /opt/campus-ops
install -d -m 0750 -o root -g campus-ops /etc/campus-ops
python3 -m venv /opt/campus-ops/venv
/opt/campus-ops/venv/bin/python -m pip install -r "$project_root/requirements.lock"
/opt/campus-ops/venv/bin/python -m pip install --no-deps "$project_root"
if [[ ! -f /etc/campus-ops/campus-ops.env ]]; then
    install -m 0640 -o root -g campus-ops "$project_root/config/ubuntu.env.example" /etc/campus-ops/campus-ops.env
fi
if [[ ! -f /etc/campus-ops/risk-policy.json ]]; then
    install -m 0640 -o root -g campus-ops "$project_root/config/risk-policy.json" /etc/campus-ops/risk-policy.json
fi
install -m 0644 "$project_root/deploy/campus-ops.service" /etc/systemd/system/campus-ops.service
systemctl daemon-reload
systemctl enable campus-ops.service
systemctl restart campus-ops.service
systemctl is-active --quiet campus-ops.service
echo "Console: http://127.0.0.1:8765 ; service logs: journalctl -u campus-ops"
