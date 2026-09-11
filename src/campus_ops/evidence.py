from __future__ import annotations

import hashlib
import json
import os
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from campus_ops.state import LiveState


def default_bundle_root() -> Path:
    root = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "CampusCyberOperationsPlatform"
    path = root / "evidence" / "incident-bundles"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, indent=2, sort_keys=True, default=str).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class EvidenceExporter:
    """Creates deterministic incident bundles with hashes for local evidence handling."""

    def __init__(self, state: LiveState, root: Path | None = None) -> None:
        self.state = state
        self.root = root or default_bundle_root()

    def export_incident(self, incident_id: str) -> dict[str, Any]:
        snapshot = self.state.snapshot()
        incident = next(
            (item for item in snapshot["incidents"] if item.get("id") == incident_id),
            None,
        )
        if incident is None:
            raise KeyError("incident not found")

        source = str(incident.get("source") or "")
        title = str(incident.get("title") or "")
        related_alerts = []
        for alert in snapshot["alerts"]:
            payload = alert.get("payload") if isinstance(alert.get("payload"), dict) else {}
            evidence = payload.get("evidence") if isinstance(payload.get("evidence"), dict) else {}
            alert_source = str(evidence.get("source") or "")
            alert_title = str(payload.get("title") or "")
            if (source and alert_source == source) or (title and alert_title == title):
                related_alerts.append(alert)

        record = {
            "schema": "campus-ops-incident-evidence-v1",
            "generated_at": datetime.now(UTC).isoformat(),
            "session_id": snapshot["session_id"],
            "network_fingerprint": snapshot["network_fingerprint"],
            "visibility_mode": snapshot["visibility_mode"],
            "incident": incident,
            "related_alerts": related_alerts,
            "capture": snapshot["capture"],
            "metrics": snapshot["metrics"],
        }
        incident_bytes = _canonical_json(record)
        incident_hash = _sha256_bytes(incident_bytes)
        manifest = {
            "schema": "campus-ops-evidence-manifest-v1",
            "incident_id": incident_id,
            "session_id": snapshot["session_id"],
            "generated_at": record["generated_at"],
            "files": {"incident.json": {"sha256": incident_hash, "bytes": len(incident_bytes)}},
        }
        manifest_bytes = _canonical_json(manifest)

        safe_id = "".join(ch for ch in incident_id if ch.isalnum() or ch in {"-", "_"})[:80]
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        path = self.root / f"incident-{safe_id}-{stamp}.zip"
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            bundle.writestr("incident.json", incident_bytes)
            bundle.writestr("manifest.json", manifest_bytes)

        return {
            "incident_id": incident_id,
            "path": str(path),
            "sha256": sha256_file(path),
            "size": path.stat().st_size,
            "incident_json_sha256": incident_hash,
            "related_alerts": len(related_alerts),
        }
