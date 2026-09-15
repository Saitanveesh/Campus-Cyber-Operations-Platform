from pathlib import Path

from campus_ops.control import EndpointControl, EnrolledEndpoint
from campus_ops.event_bus import EventBus


def test_endpoint_control_requires_explicit_enrollment(tmp_path: Path) -> None:
    registry = tmp_path / "endpoints.json"
    control = EndpointControl(EventBus(), lambda: "session", path=registry)
    endpoint = EnrolledEndpoint(
        endpoint_id="lab-01",
        name="LAB-PC-01",
        host="192.0.2.10",
        platform="windows",
        allow_rdp=True,
        allow_ssh=False,
    )
    result = control.enroll(endpoint)
    assert result["endpoint_id"] == "lab-01"
    assert control.list()[0]["allow_rdp"] is True
    assert control.remove("lab-01") is True
    assert control.list() == []
