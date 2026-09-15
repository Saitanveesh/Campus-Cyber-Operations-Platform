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

start=$SECONDS
last_state="unknown"
while (( SECONDS - start < timeout_seconds )); do
    last_state="$(systemctl is-active "$service" 2>/dev/null || true)"

    if systemctl is-failed --quiet "$service"; then
        echo "[campus-ops] $service entered failed state before the console became ready." >&2
        systemctl status "$service" --no-pager -l >&2 || true
        journalctl -u "$service" -n 80 --no-pager >&2 || true
        exit 1
    fi

    if [[ "$last_state" == "active" ]] && curl --silent --fail --max-time 2 "$url" >/dev/null 2>&1; then
        echo "[campus-ops] Console ready: $url"
        exit 0
    fi

    sleep 1
done

echo "[campus-ops] Console readiness timed out after ${timeout_seconds}s (systemd state: $last_state)." >&2
systemctl status "$service" --no-pager -l >&2 || true
journalctl -u "$service" -n 80 --no-pager >&2 || true
exit 1
