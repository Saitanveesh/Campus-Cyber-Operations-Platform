"""Explainable heuristic scoring and non-disruptive automation policy."""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class RiskPolicy:
    investigate_threshold: int = 40
    contain_threshold: int = 85
    minimum_origins: int = 2
    minimum_confidence: int = 80
    window_seconds: int = 300

    def __post_init__(self) -> None:
        for value in asdict(self).values():
            if type(value) is not int:
                raise ValueError("policy values must be integers")
        if not 0 < self.investigate_threshold <= self.contain_threshold <= 100:
            raise ValueError("invalid risk thresholds")
        if not 1 <= self.minimum_origins <= 10 or not 0 <= self.minimum_confidence <= 100:
            raise ValueError("invalid corroboration requirements")
        if not 1 <= self.window_seconds <= 300:
            raise ValueError("window must be within 1..300 seconds")


def managed_subjects(agents: list[dict]) -> dict[str, str]:
    aliases: dict[str, set[str]] = {}
    online = set()
    for row in agents:
        endpoint = str(row.get("endpoint_id") or "")
        if not endpoint:
            continue
        if row.get("status") == "ONLINE":
            online.add(endpoint)
        telemetry = row.get("telemetry") if isinstance(row.get("telemetry"), dict) else {}
        addresses = telemetry.get("network_addresses")
        names = [row.get("host"), row.get("name"), endpoint]
        if isinstance(addresses, list):
            names.extend(addresses)
        for name in names:
            if isinstance(name, str) and name.strip():
                aliases.setdefault(name.strip(), set()).add(endpoint)
    return {name: next(iter(ids)) for name, ids in aliases.items()
            if len(ids) == 1 and next(iter(ids)) in online}


def decisions(records: list[dict], agents: list[dict], *, healthy: bool,
              policy: RiskPolicy | None = None, now: float | None = None) -> list[dict]:
    policy = policy or RiskPolicy()
    now = time.time() if now is None else now
    managed = managed_subjects(agents)
    groups: dict[str, list[dict]] = {}
    for row in records:
        if row["kind"] == "ALERT" and -30 <= now - row["observed_at"] <= policy.window_seconds:
            groups.setdefault(row["subject"], []).append(row)
    result = []
    weights = {"INFO": 0, "LOW": 15, "MEDIUM": 40, "HIGH": 65, "CRITICAL": 80}
    for subject, rows in groups.items():
        origins = {r["origin"] for r in rows if r["source_time_known"]
                   and r["origin"] not in {"platform-derived", "unknown"}}
        count = len(origins)
        score = min(100, max(weights.get(r["severity"], 0) for r in rows)
                    + min(20, max(0, count - 1) * 10))
        known = all(r["source_time_known"] for r in rows)
        confidence = min(100, (40 if known else 10) + min(40, count * 20)
                         + (10 if healthy else 0))
        endpoint = managed.get(subject)
        eligible = bool(endpoint and known and healthy and score >= policy.investigate_threshold)
        blockers = ["NO_VALIDATED_LINUX_CONTAINMENT_BACKEND"]
        if not endpoint:
            blockers.append("NO_UNAMBIGUOUS_ONLINE_ENDPOINT")
        if not healthy:
            blockers.append("PIPELINE_DEGRADED")
        if not known:
            blockers.append("SOURCE_TIME_UNKNOWN")
        if count < policy.minimum_origins:
            blockers.append("INSUFFICIENT_INDEPENDENT_ORIGINS")
        if confidence < policy.minimum_confidence:
            blockers.append("CONFIDENCE_BELOW_THRESHOLD")
        if score < policy.contain_threshold:
            blockers.append("RISK_BELOW_CONTAINMENT_THRESHOLD")
        result.append({
            "target": subject, "risk_score": score, "confidence_score": confidence,
            "independent_sources": count, "high_confidence_events": 0,
            "managed": bool(endpoint), "endpoint_id": endpoint,
            "recommendation": "INVESTIGATE" if score >= policy.investigate_threshold else "OBSERVE",
            "automation_gate": "INVESTIGATE_ELIGIBLE" if eligible else "OBSERVE",
            "automatic_containment_enabled": False, "containment_blockers": blockers,
            "action_risk": {"COLLECT_SNAPSHOT": "LOW", "CONTAIN": "HIGH_UNVALIDATED"},
            "evidence_ids": [r["record_id"] for r in rows[:50]],
            "reasons": list(dict.fromkeys(r["title"] for r in rows))[:8],
            "score_semantics": "HEURISTIC_NOT_PROBABILITY",
        })
    return sorted(result, key=lambda r: r["risk_score"], reverse=True)[:100]
