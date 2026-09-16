#!/usr/bin/env bash
set -u

URL="http://127.0.0.1:8765/api/v1/live/status"

echo "===================================================="
echo " MON STABLE RUNTIME DIAGNOSTICS"
echo "===================================================="

echo_section() { printf '\n===== %s =====\n' "$1"; }

echo_section "VERSION"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    printf 'branch: '; git branch --show-current 2>/dev/null || true
    printf 'commit: '; git rev-parse --short HEAD 2>/dev/null || true
fi
curl -fsS http://127.0.0.1:8765/api/v1/system/version 2>/dev/null || true
printf '\n'

echo_section "NETWORK"
ip -br addr 2>&1 || true
printf '\nRoutes:\n'
ip route 2>&1 || true

echo_section "TSHARK"
command -v tshark || true
tshark --version 2>/dev/null | head -n 3 || true
printf '\nCapture interfaces for service account:\n'
if id campus-ops >/dev/null 2>&1; then
    sudo -u campus-ops tshark -D 2>&1 || true
else
    tshark -D 2>&1 || true
fi

echo_section "DUMPCAP HELPER"
if command -v dumpcap >/dev/null 2>&1; then
    ls -l "$(command -v dumpcap)" 2>&1 || true
    getcap "$(command -v dumpcap)" 2>&1 || true
fi

echo_section "SYSTEMD"
systemctl is-active campus-ops.service 2>&1 || true
systemctl show campus-ops.service \
    -p MainPID -p NRestarts -p User -p Group -p SupplementaryGroups \
    -p AmbientCapabilities -p CapabilityBoundingSet 2>&1 || true

echo_section "LIVE STATUS"
if payload="$(curl -fsS --max-time 4 "$URL" 2>/dev/null)"; then
    python3 -c '
import json, sys
s=json.load(sys.stdin)
network=s.get("network") or {}
live=s.get("live") or {}
capture=live.get("capture") or {}
print("version:", s.get("version"))
print("overall:", s.get("overall"))
print("session:", s.get("session_id"))
print("runtime_profile:", s.get("runtime_profile"))
print("packet_source:", s.get("authoritative_packet_source"))
print("network_interface:", network.get("interface"))
print("network_ipv4:", network.get("ipv4"))
print("gateway:", network.get("gateway"))
print("capture_state:", capture.get("state"))
print("capture_interface:", capture.get("interface"))
print("capture_backend:", capture.get("backend"))
print("capture_pid:", capture.get("process_pid"))
print("capture_activity:", capture.get("traffic_activity"))
print("packets:", capture.get("packets"))
print("bytes:", capture.get("bytes"))
print("assets:", len(live.get("assets") or []))
print("flows:", len(live.get("flows") or []))
print("alerts:", len(live.get("alerts") or []))
print("incidents:", len(live.get("incidents") or []))
print("nonhealthy_workers:")
for name,row in (s.get("workers") or {}).items():
    if isinstance(row,dict) and row.get("state") != "HEALTHY":
        print(f"  {name}: {row.get('state')} detail={row.get('detail')} error={row.get('last_error')}")
' <<<"$payload" || true
else
    echo "live status endpoint unavailable"
fi

echo_section "WATCHDOG"
curl -fsS --max-time 4 http://127.0.0.1:8765/api/v1/system/watchdog 2>/dev/null | python3 -m json.tool 2>/dev/null || true

echo_section "DEPLOYMENT CHECK"
if [[ -x /opt/campus-ops/venv/bin/python ]]; then
    sudo /opt/campus-ops/venv/bin/python -m campus_ops.deployment_check 2>&1 || true
else
    echo "/opt/campus-ops/venv/bin/python not found"
fi

echo_section "LAST SERVICE LOGS"
sudo journalctl -u campus-ops.service -n 100 --no-pager 2>&1 || true
