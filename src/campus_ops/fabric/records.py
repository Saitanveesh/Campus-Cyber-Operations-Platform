"""Normalize local sensor exports while preserving original source time and provenance."""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from datetime import UTC, datetime

from campus_ops.models import Event, EventKind, Severity


def timestamp(value: object) -> float | None:
    try:
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            result = float(value)
        else:
            parsed = datetime.fromisoformat(str(value))
            if parsed.tzinfo is None:
                return None
            result = parsed.timestamp()
        return result if math.isfinite(result) else None
    except (ValueError, TypeError, OverflowError):
        return None


def fresh(value: float | None, now: float | None = None) -> bool:
    now = datetime.now(UTC).timestamp() if now is None else now
    return value is not None and -30 <= now - value <= 300


def obj(value: object) -> dict:
    return value if isinstance(value, dict) else {}


@dataclass(frozen=True)
class EvidenceRecord:
    record_id: str
    event_id: str
    session_id: str
    source: str
    origin: str
    subject: str
    observed_at: float
    received_at: float
    kind: str
    severity: str
    rule: str
    title: str
    attributes: dict
    source_time_known: bool


def sensor_event(tool: str, sensor: str, row: dict, session: str) -> Event | None:
    origin = tool
    time_value = row.get("time") or row.get("timestamp")
    subject, rule, title = "", "", ""
    attributes = {}
    kind, severity = EventKind.OBSERVATION, Severity.INFO
    if tool == "tetragon":
        event_type = next((key for key in ("process_exec", "process_exit", "process_kprobe",
                                         "process_tracepoint", "process_lsm") if key in row), "")
        if not event_type:
            return None
        process = obj(obj(row[event_type]).get("process"))
        subject = str(row.get("node_name") or "")
        rule = event_type
        title = "Tetragon process observation"
        attributes = {k: process.get(k) for k in ("pid", "uid", "binary", "exec_id")}
    elif tool == "falco":
        fields = obj(row.get("output_fields"))
        subject = str(row.get("hostname") or fields.get("host.name") or "")
        rule = str(row.get("rule") or "")
        title = str(row.get("output") or rule)
        priority = str(row.get("priority") or "").lower()
        severity = {"emergency": Severity.CRITICAL, "alert": Severity.CRITICAL,
                    "critical": Severity.CRITICAL, "error": Severity.HIGH,
                    "warning": Severity.MEDIUM, "notice": Severity.LOW}.get(priority, Severity.INFO)
        kind = EventKind.ALERT
        attributes = {k: fields[k] for k in
                      ("proc.name", "proc.pid", "proc.exepath", "container.id", "fd.name")
                      if k in fields}
    elif tool == "wazuh":
        agent, match = obj(row.get("agent")), obj(row.get("rule"))
        subject = str(agent.get("ip") or agent.get("name") or "")
        rule = str(match.get("id") or "")
        title = str(match.get("description") or rule)
        try:
            level = int(match.get("level") or 0)
        except (TypeError, ValueError):
            return None
        severity = (Severity.CRITICAL if level >= 12 else Severity.HIGH if level >= 10
                    else Severity.MEDIUM if level >= 7 else Severity.LOW if level else Severity.INFO)
        kind = EventKind.ALERT
        decoder = str(obj(row.get("decoder")).get("name") or "").lower()
        groups = match.get("groups") if isinstance(match.get("groups"), list) else []
        # Aggregators must not create independent corroboration of a forwarded sensor.
        lineage = " ".join([decoder, *map(str, groups)]).lower()
        for native in ("suricata", "zeek", "falco"):
            if native in lineage:
                origin = native
                break
        attributes = {"agent_id": agent.get("id"), "decoder": decoder, "groups": groups[:20]}
    elif tool == "opencanary":
        subject = str(row.get("src_host") or "")
        rule = str(row.get("logtype") or "")
        title = "OpenCanary service interaction"
        time_value = row.get("utc_time")
        if isinstance(time_value, str) and timestamp(time_value) is None:
            time_value += "+00:00"
        attributes = {k: row.get(k) for k in ("src_port", "dst_host", "dst_port", "node_id")}
        kind, severity = EventKind.ALERT, Severity.MEDIUM
    elif tool == "hubble":
        flow = obj(row.get("flow")) or row
        ip = obj(flow.get("IP"))
        subject = str(ip.get("source") or "")
        time_value = flow.get("time") or time_value
        rule, title = str(flow.get("verdict") or "FLOW"), "Hubble flow observation"
        attributes = {"destination": ip.get("destination"), "verdict": flow.get("verdict"),
                      "node_name": flow.get("node_name")}
    else:
        return None
    observed = timestamp(time_value)
    if not subject.strip() or not rule or observed is None:
        return None
    return Event(
        source=f"sensor:{tool}:{sensor}", kind=kind, session_id=session, severity=severity,
        evidence_class=f"{tool.upper()}_EXPORT",
        payload={"type": "SECURITY_INDICATOR" if kind == EventKind.ALERT else "SENSOR_OBSERVATION",
                 "title": title[:512], "subject": subject.strip()[:255], "origin": origin,
                 "observed_at": observed, "rule": rule[:255], "attributes": attributes,
                 "evidence": {"source": subject.strip()[:255], **attributes}},
    )


def normalize(event: Event) -> EvidenceRecord | None:
    if not event.session_id or event.kind not in {EventKind.ALERT, EventKind.OBSERVATION}:
        return None
    payload = dict(event.payload)
    evidence = obj(payload.get("evidence"))
    subject = str(payload.get("subject") or payload.get("src_ip") or evidence.get("src_ip")
                  or evidence.get("source") or payload.get("ip") or "").strip()[:255]
    if not subject or subject in {"0.0.0.0", "::"}:
        return None
    if event.source.startswith("sensor:"):
        origin = str(payload.get("origin") or "unknown")
    elif event.source in {"zeek-feed", "suricata-feed"}:
        origin = event.source.removesuffix("-feed")
    else:
        origin = "platform-derived"
    observed = timestamp(payload.get("observed_at"))
    known = observed is not None
    if observed is None:
        observed = event.timestamp.timestamp()
    attributes = obj(payload.get("attributes")) or evidence or {
        k: v for k, v in payload.items() if k not in {"title", "observed_at", "type"}
    }
    # Bound stored untrusted payload size and ensure deterministic JSON.
    encoded = json.dumps(attributes, sort_keys=True, default=str)
    if len(encoded.encode("utf-8")) > 16384:
        attributes = {"truncated": True, "sha256": hashlib.sha256(encoded.encode()).hexdigest()}
    rule = str(payload.get("rule") or evidence.get("signature_id") or evidence.get("note")
               or payload.get("type") or "")[:255]
    title = str(payload.get("title") or payload.get("type") or rule)[:512]
    canonical = json.dumps([event.session_id, origin, subject, observed, str(event.kind),
                            str(event.severity), rule, attributes], sort_keys=True, default=str)
    return EvidenceRecord(
        hashlib.sha256(canonical.encode()).hexdigest(), event.event_id, event.session_id,
        event.source, origin, subject, observed, datetime.now(UTC).timestamp(),
        str(event.kind), str(event.severity), rule, title, attributes, known,
    )
