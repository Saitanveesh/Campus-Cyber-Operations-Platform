from campus_ops.enterprise_soc import parse_syslog_message
from campus_ops.main import build_app


def test_firewall_syslog_normalization():
    row = parse_syslog_message(
        "FIREWALL action=deny src=10.20.30.40 dst=10.20.40.50 proto=tcp dstport=445",
        "10.20.0.1",
    )
    assert row["category"] == "FIREWALL"
    assert row["action"] == "DENY"
    assert row["src_ip"] == "10.20.30.40"
    assert row["dst_ip"] == "10.20.40.50"
    assert row["protocol"] == "tcp"


def test_radius_syslog_normalization():
    row = parse_syslog_message(
        "RADIUS Access-Accept username=sai src=10.1.1.20 Calling-Station-Id=AA-BB-CC-DD-EE-FF vlan=20",
        "10.1.1.1",
    )
    assert row["category"] == "RADIUS"
    assert row["username"] == "sai"
    assert row["src_ip"] == "10.1.1.20"
    assert row["vlan"] == "20"


def test_unspecified_ip_is_not_promoted():
    row = parse_syslog_message("FIREWALL deny src=0.0.0.0 dst=224.0.0.1")
    assert row["src_ip"] is None
    assert row["dst_ip"] is None


def test_soc_routes_are_installed(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    app = build_app()
    paths = {getattr(route, "path", "") for route in app.routes}
    assert "/api/v1/system/soc-overview" in paths
    assert "/api/v1/system/infrastructure-inventory" in paths
    assert "/api/v1/admin/soc/pivot/{target}" in paths
    assert app.state.enterprise_soc_installed is True
