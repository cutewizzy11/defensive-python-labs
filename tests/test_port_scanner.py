from defensive_python_labs.recon.port_scanner import scan_range


def test_scan_range_localhost_loopback():
    # This is a smoke test that scan_range runs without raising.
    ports = scan_range("127.0.0.1", 80, 81, timeout=0.1)
    assert isinstance(ports, list)
