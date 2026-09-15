from campus_ops.workers.wifi_telemetry import parse_netsh_wlan


def test_parse_netsh_wlan_interface():
    text = """
    Name                   : Wi-Fi
    Description            : Intel Wireless Adapter
    State                  : connected
    SSID                   : LAB-NET
    BSSID                  : 00:11:22:33:44:55
    Radio type             : 802.11ax
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Channel                : 44
    Receive rate (Mbps)    : 1201
    Transmit rate (Mbps)   : 1201
    Signal                 : 91%
    """
    result = parse_netsh_wlan(text)
    assert result["ssid"] == "LAB-NET"
    assert result["bssid"] == "00:11:22:33:44:55"
    assert result["signal"] == "91%"
    assert result["channel"] == "44"
