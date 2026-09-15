# Ubuntu build risk register

| ID | Risk | Handling / remaining evidence |
|---|---|---|
| R01 | Physical Ubuntu deployment is untested | Full bootstrap CI checks packages, systemd, capture permissions and process heartbeats on Ubuntu 22.04/24.04; laptop drivers and campus load still require runtime evidence |
| R02 | Linux containment is absent | Automatic containment disabled; require implemented and validated isolation/restore backend |
| R03 | eBPF/kernel and campus throughput unmeasured | Report BTF/kernel presence only; profile with real hardware and traffic |
| R04 | Local logs are trusted input | Restrict writers/read permissions; bound lines and attributes; authenticated transport remains future work |
| R05 | SQLite is local storage | Bounded retention; backups, disk budgets and external scalable store remain needed |
| R06 | Risk/confidence are heuristics | Label explicitly; no claim of probability or calibrated coverage |
| R07 | Provenance and identity resolution incomplete | Known forwarding origins grouped; ambiguous/offline subjects cannot trigger jobs |
| R08 | Local audit lacks external anchoring | Existing case hash chain retained; protect files and add independent audit sink later |
| R09 | Queue and journal are not one transaction | Reserve before queueing; crash may miss collection; inspect journal/job results |
| R10 | Validation is temporal matching | No causal proof, attack execution, measured coverage or automatic rule promotion |
| R11 | Most ecosystem tools have no connector | Explicit status table; no blanket installation or integration claims |
| R12 | Linux interface and permissions differ from Windows | Native ip/iw/ss diagnostics; no Npcap requirement; dumpcap checked as the service account; unplug and route-loss regression tests |
| R13 | Existing local administration is not remote hardened | Keep loopback console; current admin authentication retained |
| R14 | Export tailing skips content present at first attachment/session change | Prevent stale live data; use source sensor archives for historical investigations |
| R15 | Error/drop gate is conservative and cumulative | Fix feed/queue errors and restart before automatic collection resumes |
| R16 | Package resolution can change | Application CI uses requirements.lock; host setup resolves supported ranges for the managed interpreter, runs pip check and records python-resolved.txt; full bootstrap CI exercises actual downloads |
| R17 | WSL cannot expose its host's entire network or Wi-Fi radio | Discover Linux-visible adapters only; report WSL scope; native Ubuntu or a mirror/TAP is needed for wider visibility |
| R18 | Sensor processes can fail after installation | Systemd restarts supervisors; supervisors restart failed children with backoff; stale heartbeats are not ready; installer exits 2 for partial health |
| R19 | Sensor storage and CPU consumption | Log rotation/retention configured; `any` can include duplicate traffic across bridges/tunnels; tune on the actual host |
| R20 | Existing unmanaged sensor configuration may conflict | Preserve active vendor services, mark EXTERNAL_SERVICE and require their real feed paths; do not silently take them over |
