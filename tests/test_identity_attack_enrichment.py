from pathlib import Path

from campus_ops.workers.asset_engine import _clean_hostname, _ttl_profile
from campus_ops.workers.detection import _dns_tunnel_shape


def test_ttl_profile_is_explicitly_low_confidence():
    profile = _ttl_profile("117")
    assert profile["observed_ttl"] == 117
    assert profile["estimated_initial_ttl"] == 128
    assert profile["estimated_hops"] == 11
    assert "Windows" in profile["ip_stack_hint"]
    assert profile["ip_stack_hint_confidence"] == "LOW_HEURISTIC"


def test_hostname_cleaner_rejects_service_discovery_records():
    assert _clean_hostname("lab-pc.local.") == "lab-pc.local"
    assert _clean_hostname("_googlecast._tcp.local.") == ""
    assert _clean_hostname("") == ""


def test_dns_tunnel_shape_requires_long_high_variation_labels():
    normal = "www.example.com"
    suspicious = (
        "a9f3d7c2e8b14f09d6a3c8e5b7f2d4a6c9e1f3b5."
        "telemetry.example.net"
    )
    assert not _dns_tunnel_shape(normal)
    assert _dns_tunnel_shape(suspicious)


def test_capture_requests_passive_identity_fields():
    source = Path("src/campus_ops/workers/capture.py").read_text(encoding="utf-8")
    for field in (
        '"dns.resp.name"',
        '"dns.ptr.domain_name"',
        '"llmnr.qry.name"',
        '"nbns.name"',
        '"arp.opcode"',
        '"arp.dst.proto_ipv4"',
    ):
        assert field in source


def test_investigation_ui_exposes_identity_and_security_evidence():
    ui = Path("src/campus_ops/stable_operator_ui.py").read_text(encoding="utf-8")
    investigation = Path("src/campus_ops/investigation.py").read_text(encoding="utf-8")
    assert "Identity & Exposure" in ui
    assert "Responding Services" in ui
    assert "Hostname Evidence" in ui
    assert "Security Indicators" in ui
    assert '"security_indicators": security_indicators[:50]' in investigation
    assert '"hostname_sources": asset.get("hostname_sources") or {}' in investigation


def test_detection_engine_has_passive_attack_indicators():
    source = Path("src/campus_ops/workers/detection.py").read_text(encoding="utf-8")
    for rule in (
        "TCP_SYN_RECON",
        "ADMIN_SERVICE_ATTEMPT_BURST",
        "INTERNAL_LATERAL_SWEEP",
        "ICMP_HOST_DISCOVERY",
        "DNS_TUNNEL_SHAPE",
        "ARP_DISCOVERY_SWEEP",
    ):
        assert rule in source
    assert "NOT_ATTACK_CONFIRMATION" in source
