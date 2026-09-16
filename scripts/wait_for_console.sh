#!/usr/bin/env bash
set -euo pipefail

service="campus-ops.service"
url="http://127.0.0.1:8765/api/v1/live/status"
timeout_seconds=60

while (($#)); do
    case "$1" in
        --service) service="${2:?Missing service}"; shift 2 ;;
        --url) url="${2:?Missing URL}"; shift 2 ;;
        --timeout) timeout_seconds="${2:?Missing timeout}"; shift 2 ;;
        -h|--help)
            echo 'Usage: bash scripts/wait_for_console.sh [--service UNIT] [--url URL] [--timeout SECONDS]'
            exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 64 ;;
    esac
done

[[ "$timeout_seconds" =~ ^[0-9]+$ ]] || { echo 'Timeout must be an integer number of seconds.' >&2; exit 64; }
command -v curl >/dev/null 2>&1 || { echo 'curl is required for the readiness gate.' >&2; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo 'systemctl is required for the readiness gate.' >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo 'python3 is required for the readiness gate.' >&2; exit 1; }

start=$SECONDS
last_state="unknown"
last_readiness="waiting for service"

while (( SECONDS - start < timeout_seconds )); do
    last_state="$(systemctl is-active "$service" 2>/dev/null || true)"

    if systemctl is-failed --quiet "$service"; then
        echo "[campus-ops] $service entered failed state before the monitor became ready." >&2
        systemctl status "$service" --no-pager -l >&2 || true
        journalctl -u "$service" -n 80 --no-pager >&2 || true
        exit 1
    fi

    if [[ "$last_state" == "active" ]]; then
        payload="$(curl --silent --fail --max-time 2 "$url" 2>/dev/null || true)"
        if [[ -n "$payload" ]]; then
            readiness="$(python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception as exc:
    print(f"invalid status JSON: {exc}")
    raise SystemExit(1)

session = d.get("session_id")
network = d.get("network") if isinstance(d.get("network"), dict) else {}
workers = d.get("workers") if isinstance(d.get("workers"), dict) else {}
live = d.get("live") if isinstance(d.get("live"), dict) else {}
capture = live.get("capture") if isinstance(live.get("capture"), dict) else {}
network_interface = network.get("interface")
capture_interface = capture.get("interface")
state = str(capture.get("state") or "UNKNOWN").upper()
backend = str(capture.get("backend") or "")
pid = capture.get("process_pid")
network_worker = workers.get("network-discovery")
capture_worker = workers.get("capture")
network_worker_state = (
    str(network_worker.get("state") or "UNKNOWN").upper()
    if isinstance(network_worker, dict) else "MISSING"
)
capture_worker_state = (
    str(capture_worker.get("state") or "UNKNOWN").upper()
    if isinstance(capture_worker, dict) else "MISSING"
)
try:
    pid_ok = int(pid or 0) > 0
except (TypeError, ValueError):
    pid_ok = False
interfaces_match = bool(
    network_interface and capture_interface and network_interface == capture_interface
)

if (
    session
    and interfaces_match
    and state == "ACTIVE"
    and backend == "tshark"
    and pid_ok
    and network_worker_state == "HEALTHY"
    and capture_worker_state == "HEALTHY"
):
    print(
        f"READY session={str(session)[:8]} interface={network_interface} "
        f"capture={state} pid={pid}"
    )
    raise SystemExit(0)

print(
    "NOT_READY "
    f"session={bool(session)} network={network_interface or 'none'} "
    f"capture_if={capture_interface or 'none'} capture={state} "
    f"backend={backend or 'none'} pid={pid or 'none'} "
    f"network_worker={network_worker_state} capture_worker={capture_worker_state}"
)
raise SystemExit(2)
' <<<"$payload" 2>&1)" && {
                echo "[campus-ops] Monitor ready: $readiness"
                exit 0
            }
            last_readiness="$readiness"
        fi
    fi

    sleep 1
done

echo "[campus-ops] Monitor readiness timed out after ${timeout_seconds}s (systemd state: $last_state)." >&2
echo "[campus-ops] Last readiness state: $last_readiness" >&2
systemctl status "$service" --no-pager -l >&2 || true
journalctl -u "$service" -n 80 --no-pager >&2 || true
exit 1
