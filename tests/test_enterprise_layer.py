from campus_ops.main import build_app
from campus_ops.models import NetworkCandidate
from campus_ops.workers.network_discovery import elect_network


def test_stable_runtime_excludes_enterprise_layer_routes(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    app = build_app()
    paths = {getattr(route, "path", "") for route in app.routes}
    assert "/api/v1/system/interface-decision" not in paths
    assert "/api/v1/system/enterprise-tools" not in paths
    assert "/api/v1/system/enterprise-fusion" not in paths
    assert "/api/v1/system/zeek" not in paths
    assert "/api/v1/system/diagnostics" in paths
    assert getattr(app.state, "enterprise_layer_installed", False) is False


def test_interface_election_prefers_routed_physical_adapter():
    virtual = NetworkCandidate(
        name="vEthernet (Default Switch)",
        is_up=True,
        is_loopback=False,
        ipv4=("172.20.0.1",),
        prefixes=("172.20.0.0/20",),
        default_route=False,
        bytes_recv=100000,
        bytes_sent=100000,
        category="virtual",
    )
    wifi = NetworkCandidate(
        name="Wi-Fi",
        is_up=True,
        is_loopback=False,
        ipv4=("10.20.87.183",),
        prefixes=("10.20.80.0/20",),
        default_route=True,
        route_metric=5,
        gateway="10.20.80.1",
        bytes_recv=1000,
        bytes_sent=500,
        category="wireless",
    )
    selected = elect_network([virtual, wifi])
    assert selected is not None
    assert selected.interface == "Wi-Fi"
    assert selected.default_route is True
