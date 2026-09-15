from campus_ops.workers.ioc_matcher import match_observables


def test_match_observables_matches_ip_domain_and_hash():
    payload = {
        "src_ip": "10.0.0.10",
        "dst_ip": "8.8.8.8",
        "dns_query": "api.example.com",
        "tls_sni": "",
        "http_host": "",
        "sha256": "a" * 64,
    }
    indicators = [
        {"indicator_id": "1", "kind": "IP", "value": "8.8.8.8", "severity": "HIGH"},
        {
            "indicator_id": "2",
            "kind": "DOMAIN",
            "value": "example.com",
            "severity": "MEDIUM",
        },
        {"indicator_id": "3", "kind": "SHA256", "value": "a" * 64, "severity": "HIGH"},
    ]

    matches = match_observables(payload, indicators)

    assert {item["indicator_id"] for item in matches} == {"1", "2", "3"}
    domain = next(item for item in matches if item["indicator_id"] == "2")
    assert domain["observable"] == "api.example.com"


def test_match_observables_does_not_match_unrelated_domain_suffix():
    matches = match_observables(
        {"dns_query": "notexample.com"},
        [{"indicator_id": "1", "kind": "DOMAIN", "value": "example.com"}],
    )
    assert matches == []
