from campus_ops.workers.arp_guard import ArpGuardWorker


def test_arp_guard_rejects_probe_and_special_addresses():
    assert ArpGuardWorker._valid_arp_ip("0.0.0.0") is None
    assert ArpGuardWorker._valid_arp_ip("127.0.0.1") is None
    assert ArpGuardWorker._valid_arp_ip("224.0.0.1") is None
    assert ArpGuardWorker._valid_arp_ip("255.255.255.255") is None
    assert ArpGuardWorker._valid_arp_ip("10.20.80.22") == "10.20.80.22"


def test_arp_guard_accepts_only_unicast_mac_addresses():
    assert ArpGuardWorker._valid_unicast_mac("00:11:22:33:44:55") == "00:11:22:33:44:55"
    assert ArpGuardWorker._valid_unicast_mac("00-11-22-33-44-55") == "00:11:22:33:44:55"
    assert ArpGuardWorker._valid_unicast_mac("00:00:00:00:00:00") is None
    assert ArpGuardWorker._valid_unicast_mac("ff:ff:ff:ff:ff:ff") is None
    assert ArpGuardWorker._valid_unicast_mac("01:00:5e:00:00:01") is None
