from pathlib import Path

from campus_ops.models import EventKind
from campus_ops.workers.zeek_feed import ZeekFeedWorker


def test_zeek_connection_normalization():
    event = ZeekFeedWorker._event_for(
        Path("conn.log"),
        {
            "uid": "C1",
            "id.orig_h": "10.20.80.25",
            "id.orig_p": 51000,
            "id.resp_h": "10.20.80.10",
            "id.resp_p": 445,
            "proto": "tcp",
            "service": "smb",
            "orig_bytes": 200,
            "resp_bytes": 800,
        },
        "session-1",
    )
    assert event is not None
    assert event.kind == EventKind.OBSERVATION
    assert event.evidence_class == "ZEEK_CONN"
    assert event.payload["src_ip"] == "10.20.80.25"
    assert event.payload["dst_port"] == 445


def test_zeek_notice_is_security_alert():
    event = ZeekFeedWorker._event_for(
        Path("notice.log"),
        {"note": "Scan::Port_Scan", "msg": "scan candidate", "src_ip": "10.20.80.25"},
        "session-1",
    )
    assert event is not None
    assert event.kind == EventKind.ALERT
    assert event.evidence_class == "ZEEK_NOTICE"
