from campus_ops.policy import ControlAction, PolicyEngine, Role


def test_policy_blocks_response_for_observer():
    policy = PolicyEngine()
    assert not policy.authorize(Role.OBSERVER, ControlAction.STOP_PROCESS).allowed


def test_incident_responder_can_collect_snapshot_and_quarantine():
    policy = PolicyEngine()
    assert policy.authorize(Role.INCIDENT_RESPONDER, ControlAction.COLLECT_SNAPSHOT).allowed
    assert policy.authorize(Role.INCIDENT_RESPONDER, ControlAction.QUARANTINE_FILE).allowed
