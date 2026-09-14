# Ubuntu deployment

Target: Ubuntu 24.04+ with Python 3.12+. This repository has not yet been qualified on the user's physical systems.

## Install

From the repository checkout:

```bash
sudo bash scripts/install_ubuntu.sh
sudo systemctl status campus-ops --no-pager
sudo journalctl -u campus-ops -n 100 --no-pager
```

The installer creates a dedicated service account, installs the application into /opt/campus-ops/venv, stores state under /var/lib/campus-ops and preserves existing /etc/campus-ops configuration. The console listens on its existing loopback address. The UI sources and black-and-white design are unchanged.

Packet acquisition uses dumpcap file capabilities and the wireshark group; Python does not run as root. The service intentionally does not set NoNewPrivileges because that would prevent acquiring dumpcap's file capabilities. Review packet permissions on the target host and after package upgrades.

## Sensor exports

Deploy the sensors separately. Configure JSON export files in /etc/campus-ops/campus-ops.env using config/ubuntu.env.example. Grant the campus-ops account read/traverse access to the chosen files and their parent directories, including rotated logs. Protect those files from untrusted writers. Do not grant write access to sensor logs.

Zeek must produce JSON logs. Suricata must produce EVE JSON. The five additional export adapters require the identity and original timestamp fields described in TOOL_INTEGRATIONS.md. Readers skip existing content at first attachment or session changes.

Restart the service after configuration changes. Check /api/v1/system/operations-fabric and the Zeek/syslog status endpoints. A configured path or installed binary alone is not proof of received telemetry.

## Risk policy

Default mode is observe. Set CAMPUS_OPS_AUTONOMY_MODE=investigate to permit bounded snapshots of unambiguous online enrolled endpoints. Configure CAMPUS_OPS_RISK_POLICY=/etc/campus-ops/risk-policy.json to use the supplied thresholds. Linux containment is not implemented and stays disabled.

For manual development:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m pip install --no-deps -e .
CAMPUS_OPS_NO_BROWSER=1 .venv/bin/python -m campus_ops
```

Validation: ruff check src tests; bash -n scripts/install_ubuntu.sh; pytest -q. Ubuntu CI also checks that UI files have not changed from the reconstruction base.
