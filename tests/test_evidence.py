import json
import zipfile
from pathlib import Path

from campus_ops.evidence import EvidenceExporter, sha256_file
from campus_ops.state import LiveState


def test_incident_bundle_contains_manifest_and_hashes(tmp_path: Path) -> None:
    state = LiveState()
    state.start_session("session-1", "network-fingerprint")
    state.add_incident(
        "incident-1",
        {
            "id": "incident-1",
            "title": "Possible reconnaissance",
            "source": "10.0.0.8",
            "severity": "HIGH",
            "status": "OPEN",
        },
    )
    exporter = EvidenceExporter(state, tmp_path)

    result = exporter.export_incident("incident-1")
    path = Path(result["path"])

    assert path.exists()
    assert result["sha256"] == sha256_file(path)
    with zipfile.ZipFile(path) as bundle:
        assert set(bundle.namelist()) == {"incident.json", "manifest.json"}
        record = json.loads(bundle.read("incident.json"))
        manifest = json.loads(bundle.read("manifest.json"))
    assert record["incident"]["id"] == "incident-1"
    assert manifest["incident_id"] == "incident-1"
    assert len(manifest["files"]["incident.json"]["sha256"]) == 64
