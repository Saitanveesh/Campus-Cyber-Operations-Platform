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
    ubuntu) installer="scripts/install_ubuntu_stable.sh" ;;
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

info "Updating $BRANCH from GitHub."
git pull --ff-only origin "$BRANCH"

info "Installing stable single-source profile."
sudo bash "$installer" --interface auto

build_commit="$(git rev-parse HEAD)"
build_branch="$(git branch --show-current)"
build_installed_at="$(date --utc +%Y-%m-%dT%H:%M:%SZ)"
build_dirty=false
if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
    build_dirty=true
fi
sudo install -d -m 0750 -o root -g campus-ops /etc/campus-ops
build_tmp="$(mktemp)"
cat > "$build_tmp" <<EOF
{
  "branch": "$build_branch",
  "commit": "$build_commit",
  "installed_at": "$build_installed_at",
  "source_dirty": $build_dirty,
  "runtime_profile": "stable-single-source"
}
EOF
sudo install -m 0640 -o root -g campus-ops "$build_tmp" /etc/campus-ops/build.json
rm -f "$build_tmp"
info "Build provenance: $build_branch @ ${build_commit:0:12}"

sudo systemctl daemon-reload
sudo systemctl restart campus-ops.service

info "Waiting for the managed console to become ready."
if ! sudo bash scripts/wait_for_console.sh --url "$CONSOLE_URL/api/v1/live/status" --timeout 60; then
    fail "campus-ops.service did not become ready. Diagnostics were printed above."
fi

info "Running post-install health check."
sudo /opt/campus-ops/venv/bin/python -m campus_ops.deployment_check

info "Console: $CONSOLE_URL"
if [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]] && command -v xdg-open >/dev/null 2>&1; then
    (xdg-open "$CONSOLE_URL" >/dev/null 2>&1 &) || true
fi

exit 0
