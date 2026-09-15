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

invoking_user="${SUDO_USER:-${USER:-}}"
info "Installing/repairing prerequisites and forcing automatic active-interface selection."
# The installer uses exit 2 for a PARTIAL deployment (for example an optional Falco
# block or a capture check that still needs permission repair). Do not abort before
# the repair stage. Fatal installer errors still stop immediately.
installer_status=0
sudo bash "$installer" --interface auto || installer_status=$?
if [[ "$installer_status" -ne 0 && "$installer_status" -ne 2 ]]; then
    fail "Installer stopped with fatal status $installer_status. See /var/lib/campus-ops/install/bootstrap.log"
fi
if [[ "$installer_status" -eq 2 ]]; then
    info "Installer reported PARTIAL; continuing mandatory repair and final validation."
fi

info "Repairing and verifying packet-capture privileges for the service account."
sudo bash scripts/repair_capture_permissions.sh --user "$invoking_user"

# Ensure the just-pulled source is the code actually executing in /opt. The installer
# normally performs this step, but an existing installation must never keep a stale
# wheel after a branch update.
info "Deploying the current monitor-v1 source into the managed virtual environment."
sudo /opt/campus-ops/venv/bin/python -m pip install --force-reinstall --no-deps "$root"

sudo systemctl daemon-reload
sudo systemctl restart campus-ops.service

# A systemd restart returns before Uvicorn has necessarily completed application startup.
# Never run health checks against a socket that is still being created. The readiness
# helper suppresses normal connection-refused races and emits service logs only if the
# console genuinely fails to become available.
info "Waiting for the managed console to become ready."
if ! sudo bash scripts/wait_for_console.sh --url "$CONSOLE_URL/api/v1/live/status" --timeout 60; then
    fail "campus-ops.service did not become ready. Diagnostics were printed above."
fi

info "Running post-install health check."
health_status=0
sudo /opt/campus-ops/venv/bin/python -m campus_ops.deployment_check || health_status=$?
if [[ "$health_status" -eq 0 ]]; then
    info "Deployment check passed."
else
    info "Deployment is running but one or more optional/core checks need attention; see the report above."
fi

info "Console: $CONSOLE_URL"
# Open only in the invoking desktop session; the system service itself remains headless.
if [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]] && command -v xdg-open >/dev/null 2>&1; then
    (xdg-open "$CONSOLE_URL" >/dev/null 2>&1 &) || true
fi

# A PARTIAL optional integration should not block use of the console, but a console that
# never becomes reachable is a fatal bootstrap problem and is handled by the gate above.
exit 0
