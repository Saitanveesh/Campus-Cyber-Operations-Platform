from types import SimpleNamespace

from campus_ops.network_depth_layer import (
    build_dns_tls_report,
    build_ipv6_report,
    build_physical_topology_evidence,
    build_segmentation_report,
    build_target_network_dossier,
)


class FakeOrchestrator:
    def __init__(self):
        self.state = SimpleNamespace()

    def get_network_context(self):
        return {
            "interface": "Wi-Fi",
            "prefixes": ["192.168.50.0/24", "2001:db8:1::/64"],
            "ipv4": ["192.168.50.10"],
            "ipv6": ["2001:db8:1::10"],
        }

    def snapshot(self):
        return {
            "live": {
                "assets": [
                    {"ip": "192.168.50.10"},
                    {"ip": "2001:db8:1::20"},
                ],
                "flows": [
                    {
                        "src_ip": "192.168.50.10",
                        "dst_ip": "8.8.8.8",
                        "protocol": "TCP",
                        "service": "HTTPS",
                    },
                    {
                        "src_ip": "2001:db8:1::20",
                        "dst_ip": "2001:4860:4860::8888",
                        "protocol": "UDP",
                        "service": "DNS",
                    },
                ],
                "events": [
                    {
                        "payload": {
                            "type": "ZEEK_OBSERVATION",
                            "src_ip": "192.168.50.10",
                            "dst_ip": "8.8.8.8",
                            "dns_query": "example.org",
                            "tls_sni": "example.org",
                        }
                    },
                    {
                        "payload": {
                            "type": "SNMP_TELEMETRY",
                            "target": "192.168.50.1",
                            "sysName": "CORE-SW-01",
                            "lldp_neighbors": [
                                {
                                    "local_port": "Gi1/0/1",
                                    "remote_system": "SW-L01",
                                    "remote_port": "Gi0/1",
                                }
                            ],
                        }
                    },
                ],
                "alerts": [],
                "packet_feed": [],
            }
        }


def fake_app():
    return SimpleNamespace(state=SimpleNamespace(orchestrator=FakeOrchestrator()))


def test_network_depth_reports_only_observed_truth():
    app = fake_app()
    ipv6 = build_ipv6_report(app)
    dns_tls = build_dns_tls_report(app)
    segmentation = build_segmentation_report(app)
    topology = build_physical_topology_evidence(app)

    assert ipv6["state"] == "OBSERVED"
    assert "2001:db8:1::20" in ipv6["addresses"]
    assert dns_tls["dns"][0]["name"] == "example.org"
    assert segmentation["vlan_state"] == "UNKNOWN_WITHOUT_LLDP_SNMP_CONTROLLER_EVIDENCE"
    assert topology["state"] == "EVIDENCE_PRESENT"
    assert topology["links"][0]["remote"] == "SW-L01"


def test_target_network_dossier_is_current_session_only():
    report = build_target_network_dossier(fake_app(), "192.168.50.10")
    assert report["classification"] == "PRIVATE"
    assert report["current_session_only"] is True
    assert report["flow_count"] == 1
    assert report["truth_state"] == "EVIDENCE_PRESENT"
