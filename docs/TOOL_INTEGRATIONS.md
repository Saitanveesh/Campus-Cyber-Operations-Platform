# Tool integration status

This file distinguishes implemented ingestion from intended ecosystem scope. The installer does not install this entire list, and executable presence does not prove a working connector.

| Tools | Current status | Intended role |
|---|---|---|
| Zeek, Suricata | Implemented local JSON ingestion; physical deployment unvalidated | Network metadata and signature alerts |
| Tetragon, Falco, Hubble, Wazuh, OpenCanary | Implemented local JSONL export adapters; physical deployment unvalidated | Endpoint, flow, alert and deception evidence |
| Pixie, Cilium, bcc, bpftrace, Inspektor Gadget | No new operational connector | Kubernetes/eBPF observability and enforcement |
| Neo4j, BloodHound Enterprise | No operational connector; current graph uses SQLite | Evidence and identity relationships; BloodHound requires a relevant identity estate |
| Velociraptor, Arkime | Registry/presence checks only | DFIR collection and indexed packet access |
| T-Pot | No operational connector | Deception telemetry |
| MITRE Caldera, Infection Monkey, Atomic Red Team, VECTR, DeTTECT, PurpleSharp | No exercise execution connector | Authorized lab validation and coverage management; PurpleSharp is Windows-oriented |
| TheHive, MISP, OpenCTI | No operational connector | Cases and threat intelligence exchange |
| Teleport, Ngrok, Chisel, Ligolo-ng, SSHuttle | No operational connector | Explicitly scoped access/lab connectivity |
| Illumio, Akamai Guardicore, Cisco Secure Workload (Tetration), VMware NSX, Zero Networks, Zscaler Private Access (ZPA), AppGate SDP, Elisity, ColorTokens, AccuKnox | No operational connector | Managed segmentation/control, dependent on deployment and licensing |
| Metasploit Framework / Pro, Burp Suite Professional, CrackMapExec / NetExec, Impacket, Evil-WinRM, Responder | No operational connector | Authorized lab testing; some workflows target Windows identity/services |
| Sliver, Mythic, Havoc, Cobalt Strike, Covenant, Brute Ratel C4, Nighthawk, Empire, Merlin | No operational connector | Isolated authorized adversary-emulation scope |

Ubuntu hosts do not make Windows-specific tools or commercial control planes automatically applicable. Kernel probes, Kubernetes components, external services and licensed products need their own deployment plans.

Export contracts: Tetragon JSON event objects; Falco JSON output with rule/priority/hostname/time; Wazuh alerts JSON with agent/rule/timestamp; OpenCanary JSON with src_host/logtype/utc_time; Hubble JSON flow objects with IP/time. Required identity/time fields must be present. Fixture tests establish parser behavior, not compatibility with every product version.
