from campus_ops.config import Settings
from campus_ops.orchestrator import Orchestrator


def test_snapshot_has_live_contract_before_start():
    orch = Orchestrator(Settings())
    snapshot = orch.snapshot()
    assert snapshot["live_contract"] == "CURRENT_SESSION_ONLY"
    assert snapshot["session_id"] is None
    assert set(snapshot["workers"]) == {"network-discovery", "tool-probe"}
