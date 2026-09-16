# MON Stable 0.5.0 Architecture

## Data plane

```text
selected interface
      |
    TShark
      |
 packet observations
      |
 EventBus -> LiveState
      |
 protocol / asset / flow / topology / application / DNS / service / TCP
 baseline / performance / ARP guard / behaviour / beaconing / DoS / incidents
      |
 stable API -> stable console
```

TShark is the only live packet source. MON does not start a second packet collector, IDS engine or flow receiver in stable mode. `dumpcap` may be used internally by Wireshark/TShark as the Linux privilege helper; MON does not manage it as an independent acquisition pipeline.

## Control plane

`NetworkDiscoveryWorker` elects one eligible active interface. The session manager subscribes only to network-discovery control events, so high-rate packet events cannot crowd out interface/session transitions. Interface loss requires repeated missing observations; material network identity changes also require confirmation.

Capture state follows the managed TShark process. Packet silence changes only `traffic_activity` to `QUIET`; it does not mark capture down or recreate the session.

## Stable workers

The stable orchestrator constructs only the workers required to derive current passive state from that packet stream:

- state sink and network discovery
- capture and host interface telemetry
- protocol, asset, flow and topology engines
- application, DNS, service and TCP intelligence
- traffic baseline and performance
- ARP guard, deterministic behaviour detection, beaconing and DoS warning
- incident correlation and stale-state cleanup

The stable runtime has no endpoint agent plane, response engine, remote shell, isolation/quarantine, active network probe, secondary sensor feed, malware scanner, voice pipeline or enterprise console layer.

## Truth model

Assets are not every IP seen in packets. A local asset requires local-scope source evidence, a valid unicast source MAC and repeated source-frame observations. Remote/off-subnet addresses can appear as observed peers in Traffic or Topology when packets actually contain them.

Topology and Path Space show observed communication relationships. They do not claim physical switch/router hops unless independent infrastructure telemetry exists; stable 0.5.0 does not enable such telemetry.

## API/UI

`stable_api.py` exposes current live state and health only. `stable_ui.py` serves the compact stable console and injects the passive Topology, Path Space, Investigation and Forensics views. Investigation/Forensics are local authenticated evidence pivots and do not execute network probes.
