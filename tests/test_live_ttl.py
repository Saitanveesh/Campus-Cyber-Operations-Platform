from datetime import UTC, datetime, timedelta

from campus_ops.state import LiveState


def test_prune_stale_live_entities_only() -> None:
    state = LiveState()
    state.start_session("session-a")
    now = datetime.now(UTC)
    old = (now - timedelta(minutes=20)).isoformat()
    fresh = now.isoformat()

    state.upsert_asset("old", {"ip": "10.0.0.2", "last_seen": old})
    state.upsert_asset("fresh", {"ip": "10.0.0.3", "last_seen": fresh})
    state.upsert_flow("old-flow", {"last_seen": old})
    state.upsert_flow("fresh-flow", {"last_seen": fresh})
    state.upsert_edge("old-edge", {"last_seen": old})
    state.upsert_edge("fresh-edge", {"last_seen": fresh})

    removed = state.prune_stale(
        now=now,
        asset_ttl_seconds=600,
        flow_ttl_seconds=180,
        edge_ttl_seconds=180,
    )

    assert removed == {"assets": 1, "flows": 1, "edges": 1}
    snapshot = state.snapshot()
    assert [item["ip"] for item in snapshot["assets"]] == ["10.0.0.3"]
    assert len(snapshot["flows"]) == 1
    assert len(snapshot["topology_edges"]) == 1
    assert snapshot["metrics"]["last_prune_removed"] == 3
