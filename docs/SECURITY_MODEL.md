# MON Stable Security Model

MON Stable 0.5.0 is a passive monitoring service. It observes traffic visible to the selected interface and derives current-session state from one managed TShark process.

## Privilege boundary

The systemd service runs as the dedicated `campus-ops` account. Linux capture access is provided through the Wireshark group/dumpcap capabilities and the service capability set required for packet capture. The web console binds to loopback by default.

## Operator workspace

Investigation and Forensics are local-only authenticated views. Their backend operates only on evidence already present in the current MON snapshot. It does not run ping, traceroute, Nmap, PowerShell, remote shell, isolation, quarantine or endpoint-control operations.

Override the local operator credential with:

```text
CAMPUS_OPS_OPERATOR_USER=<operator>
CAMPUS_OPS_OPERATOR_PASSWORD=<strong-password>
```

The development default exists for local lab convenience and should not be retained on a shared host.

## Data handling

Stable MON keeps live monitoring state in memory. The release does not mount the former forensic-capture/evidence-export, agent, response or secondary-sensor pipelines. Repository ignore rules exclude common packet-capture, key and evidence file types.

## Visibility and claims

An address observed in a packet is not automatically a local asset. Local asset promotion requires repeated local source-frame evidence. Communication edges are packet-observed relationships, not claimed physical network hops. Wider network visibility depends on legitimate sensor placement such as a SPAN/mirror port, TAP or gateway/bridge position.
