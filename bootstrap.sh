#!/usr/bin/env bash
set -euo pipefail

REPO="Saitanveesh/Campus-Cyber-Operations-Platform"
BRANCH="monitor-v1"
CONSOLE_URL="http://127.0.0.1:8765"

fail() { echo "[campus-ops] ERROR: $*" >&2; exit 1; }
info() { echo "[campus-ops] $*"; }

command -v git >/dev/null 2>&1 || fail "git is required. Install it with: sudo apt update && sudo apt install -y git"
[[ -f /etc/os-release ]] || fail "Linux distribution metadata not found."
# shellcheck disable=SC1091
source /etc/os-release

case "${ID:-}" in
    ubuntu) installer="scripts/install_ubuntu.sh" ;;
    kali) installer="scripts/install_kali.sh" ;;
    *) fail "Supported deployment hosts are Ubuntu 22.04+ and Kali Linux. Detected: ${PRETTY_NAME:-unknown}." ;;
esac

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$root"
[[ -d .git ]] || fail "Run bootstrap.sh from the cloned $REPO repository."

current_branch="$(git branch --show-current)"
if [[ "$current_branch" != "$BRANCH" ]]; then
    info "Switching from ${current_branch:-detached HEAD} to $BRANCH."
    git fetch origin "$BRANCH"
    git checkout "$BRANCH"
fi

# Never discard local work. A dirty tree is kept; pull --ff-only will stop rather than overwrite it.
info "Updating $BRANCH from GitHub."
git pull --ff-only origin "$BRANCH"

info "Installing/repairing prerequisites and forcing automatic active-interface selection."
sudo bash "$installer" --interface auto

info "Running post-install health check."
if sudo /opt/campus-ops/venv/bin/python -m campus_ops.deployment_check; then
    info "Deployment check passed."
else
    info "Deployment is running but one or more optional/core checks need attention; see the report above."
fi

if command -v curl >/dev/null 2>&1; then
    for _ in $(seq 1 20); do
        if curl -fsS "$CONSOLE_URL/api/v1/live/status" >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
fi

info "Console: $CONSOLE_URL"
# Open only in the invoking desktop session; the system service itself remains headless.
if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != root ]]; then
    desktop_user="$SUDO_USER"
else
    desktop_user="${USER:-}"
fi
if [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]] && command -v xdg-open >/dev/null 2>&1; then
    (xdg-open "$CONSOLE_URL" >/dev/null 2>&1 &) || true
fi
