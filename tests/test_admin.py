from campus_ops.admin import AdminSessionStore, _admin_targets


def test_admin_bootstrap_credentials_and_session(monkeypatch):
    monkeypatch.delenv("CAMPUS_OPS_ADMIN_USER", raising=False)
    monkeypatch.delenv("CAMPUS_OPS_ADMIN_PASSWORD", raising=False)
    store = AdminSessionStore(ttl_seconds=60)
    assert store.default_password is True
    assert store.login("admin", "wrong") is None
    token = store.login("admin", "123")
    assert token
    assert store.validate(token) is True
    store.logout(token)
    assert store.validate(token) is False


def test_admin_password_can_be_overridden(monkeypatch):
    monkeypatch.setenv("CAMPUS_OPS_ADMIN_PASSWORD", "lab-secret")
    store = AdminSessionStore(ttl_seconds=60)
    assert store.default_password is False
    assert store.login("admin", "123") is None
    assert store.login("admin", "lab-secret")


def test_admin_targets_marks_agent_and_remote_access():
    snapshot = {
        "live": {
            "assets": [
                {
                    "ip": "10.0.0.20",
                    "hostname": "LAB-PC-20",
                    "classification": "LOCAL_SUBNET_ENDPOINT",
                    "last_seen": "2026-09-12T04:00:00+00:00",
                    "packets_as_source": 22,
                }
            ]
        },
        "managed_agents": [
            {
                "endpoint_id": "lab20",
                "name": "LAB-PC-20",
                "status": "ONLINE",
                "telemetry": {
                    "network_addresses": [{"address": "10.0.0.20"}],
                    "isolation_state": "NORMAL",
                },
            }
        ],
        "enrolled_endpoints": [
            {
                "endpoint_id": "remote20",
                "name": "LAB-PC-20",
                "host": "10.0.0.20",
                "platform": "windows",
                "allow_rdp": True,
                "allow_ssh": True,
            }
        ],
    }
    rows = _admin_targets(snapshot)
    assert len(rows) == 1
    assert rows[0]["managed"] is True
    assert rows[0]["remote_enrolled"] is True
    assert rows[0]["allow_ssh"] is True
    assert rows[0]["allow_rdp"] is True
