#!/usr/bin/env bash
set -euo pipefail

[[ "$(id -u)" == 0 ]] || { echo 'Run this helper with sudo.' >&2; exit 1; }
manual_user=""
while (($#)); do
    case "$1" in
        --user) manual_user="${2:?Missing user}"; shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 64 ;;
    esac
done

command -v dumpcap >/dev/null 2>&1 || { echo 'dumpcap not found; install Wireshark/TShark first.' >&2; exit 1; }
getent group wireshark >/dev/null || groupadd --system wireshark
if id campus-ops >/dev/null 2>&1; then
    usermod -a -G wireshark campus-ops
fi
if [[ -n "$manual_user" && "$manual_user" != root ]] && id "$manual_user" >/dev/null 2>&1; then
    usermod -a -G wireshark "$manual_user"
fi

dumpcap_path="$(command -v dumpcap)"
chown root:wireshark "$dumpcap_path"
chmod 0750 "$dumpcap_path"
setcap cap_net_raw,cap_net_admin=eip "$dumpcap_path"

# Verify the service identity now; it does not need an interactive logout/login.
if id campus-ops >/dev/null 2>&1; then
    if runuser -u campus-ops -- "$dumpcap_path" -D >/dev/null 2>&1; then
        echo "Packet capture permission verified for campus-ops using $dumpcap_path."
    else
        echo 'WARNING: campus-ops still cannot enumerate capture interfaces.' >&2
        exit 2
    fi
fi
if [[ -n "$manual_user" && "$manual_user" != root ]]; then
    echo "Added $manual_user to wireshark. Manual TShark shells require a new login session; the campus-ops systemd service works immediately."
fi
