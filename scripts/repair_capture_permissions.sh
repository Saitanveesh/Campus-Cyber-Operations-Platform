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
command -v tshark >/dev/null 2>&1 || { echo 'tshark not found; install Wireshark/TShark first.' >&2; exit 1; }
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

# tcpdump is the runtime fallback if dumpcap cannot acquire on a particular host/kernel.
tcpdump_path="$(command -v tcpdump || true)"
if [[ -n "$tcpdump_path" ]]; then
    chown root:wireshark "$tcpdump_path"
    chmod 0750 "$tcpdump_path"
    setcap cap_net_raw,cap_net_admin=eip "$tcpdump_path"
fi

capture_user=campus-ops
if ! id "$capture_user" >/dev/null 2>&1; then
    echo "WARNING: $capture_user account does not exist yet; skipping runtime capture verification." >&2
    exit 0
fi

# First verify enumeration, then prove an actual one-second capture can be opened as the
# exact service identity. This catches systems where `dumpcap -D` succeeds but opening
# the selected interface still fails.
if ! runuser -u "$capture_user" -- "$dumpcap_path" -D >/dev/null 2>&1; then
    echo "ERROR: $capture_user cannot enumerate dumpcap interfaces after permission repair." >&2
    getcap "$dumpcap_path" >&2 || true
    id "$capture_user" >&2 || true
    exit 2
fi

interface="$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
if [[ -z "$interface" ]]; then
    interface="$(ip -o link show up 2>/dev/null | awk -F': ' '$2 != "lo" {sub(/@.*/, "", $2); print $2; exit}')"
fi
if [[ -z "$interface" ]]; then
    echo 'WARNING: no active non-loopback interface is available for an end-to-end capture test.' >&2
    exit 0
fi

workdir="$(mktemp -d /tmp/campus-ops-capture-check.XXXXXX)"
trap 'rm -rf "$workdir"' EXIT
chown "$capture_user":campus-ops "$workdir"
chmod 0750 "$workdir"

verify_backend() {
    local backend="$1"
    local output="$workdir/${backend}.pcapng"
    case "$backend" in
        dumpcap)
            runuser -u "$capture_user" -- "$dumpcap_path" -q -i "$interface" -a duration:1 -w "$output" >/dev/null 2>"$workdir/${backend}.err" || return 1
            ;;
        tcpdump)
            [[ -n "$tcpdump_path" ]] || return 1
            runuser -u "$capture_user" -- "$tcpdump_path" -U -n -i "$interface" -G 1 -W 1 -w "$output" >/dev/null 2>"$workdir/${backend}.err" || return 1
            ;;
        *) return 1 ;;
    esac
    [[ -s "$output" ]] || return 1
    # Decoder validation is intentionally read-only. Zero captured packets is acceptable;
    # inability to parse the pcap is not.
    runuser -u "$capture_user" -- tshark -n -r "$output" -c 1 >/dev/null 2>"$workdir/tshark.err" || return 1
    return 0
}

if verify_backend dumpcap; then
    echo "Packet capture verified end-to-end for $capture_user on $interface using dumpcap + TShark."
elif verify_backend tcpdump; then
    echo "dumpcap could not acquire on $interface; tcpdump + TShark fallback verified for $capture_user."
    sed -n '1,12p' "$workdir/dumpcap.err" >&2 || true
else
    echo "ERROR: neither dumpcap nor tcpdump can capture $interface as $capture_user." >&2
    echo 'dumpcap diagnostics:' >&2
    sed -n '1,20p' "$workdir/dumpcap.err" >&2 || true
    echo 'tcpdump diagnostics:' >&2
    sed -n '1,20p' "$workdir/tcpdump.err" >&2 || true
    echo 'capabilities:' >&2
    getcap "$dumpcap_path" "$tcpdump_path" 2>/dev/null >&2 || true
    echo 'service identity:' >&2
    id "$capture_user" >&2 || true
    exit 2
fi

if [[ -n "$manual_user" && "$manual_user" != root ]]; then
    echo "Added $manual_user to wireshark. Open a new login shell before manual packet-capture commands."
fi
