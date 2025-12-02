import socket
from typing import List


def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """Return True if TCP connection to host:port succeeds within timeout.

    Simple educational scanner; not optimized or stealthy.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            return True
        except OSError:
            return False


def scan_range(host: str, start_port: int, end_port: int, timeout: float = 1.0) -> List[int]:
    """Scan ports in [start_port, end_port] and return a list of open ports."""
    open_ports: List[int] = []
    for port in range(start_port, end_port + 1):
        if scan_port(host, port, timeout=timeout):
            open_ports.append(port)
    return open_ports
