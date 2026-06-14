"""
Threaded TCP port scanner with banner grabbing and service detection.

Educational use only. Only scan hosts you own or have explicit permission to test.
"""

from __future__ import annotations

import socket
import concurrent.futures
from dataclasses import dataclass, field
from typing import List, Optional, Dict

# Common port → service name mapping
COMMON_SERVICES: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}


@dataclass
class PortResult:
    port: int
    open: bool
    service: str = ""
    banner: str = ""


def _grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    """Attempt to grab a service banner from an open port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            # Send a generic HTTP probe; many services respond anyway
            try:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            except Exception:
                pass
            banner = s.recv(1024).decode("utf-8", errors="replace").strip()
            return banner[:200]  # cap at 200 chars
    except Exception:
        return ""


def scan_port(host: str, port: int, timeout: float = 1.0, grab_banner: bool = False) -> PortResult:
    """
    Scan a single TCP port.

    Parameters
    ----------
    host : str
        Target hostname or IP address.
    port : int
        Port number to scan.
    timeout : float
        Connection timeout in seconds.
    grab_banner : bool
        If True, attempt to read the service banner on open ports.

    Returns
    -------
    PortResult
        Dataclass with port, open status, service name, and banner.

    Examples
    --------
    >>> result = scan_port("127.0.0.1", 80)
    >>> result.port
    80
    """
    result = PortResult(port=port, open=False)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            result.open = True
            result.service = COMMON_SERVICES.get(port, "Unknown")
            if grab_banner:
                result.banner = _grab_banner(host, port, timeout=timeout)
        except OSError:
            pass
    return result


def scan_range(
    host: str,
    start_port: int,
    end_port: int,
    timeout: float = 1.0,
    max_workers: int = 100,
    grab_banner: bool = False,
) -> List[PortResult]:
    """
    Scan a range of ports using a thread pool for speed.

    Parameters
    ----------
    host : str
        Target hostname or IP.
    start_port : int
        First port in range (inclusive).
    end_port : int
        Last port in range (inclusive).
    timeout : float
        Per-port connection timeout.
    max_workers : int
        Number of concurrent threads (default 100).
    grab_banner : bool
        If True, attempt banner grabbing on open ports.

    Returns
    -------
    List[PortResult]
        Only the open ports, sorted by port number.

    Examples
    --------
    >>> results = scan_range("127.0.0.1", 1, 1024)
    >>> all(r.open for r in results)
    True
    """
    ports = range(start_port, end_port + 1)
    open_ports: List[PortResult] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_port, host, port, timeout, grab_banner): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result.open:
                open_ports.append(result)

    return sorted(open_ports, key=lambda r: r.port)


def scan_common_ports(host: str, timeout: float = 1.0, grab_banner: bool = True) -> List[PortResult]:
    """
    Scan only the well-known ports listed in COMMON_SERVICES.

    Faster than a full range scan — good for a quick fingerprint.

    Examples
    --------
    >>> results = scan_common_ports("127.0.0.1")
    >>> isinstance(results, list)
    True
    """
    ports = list(COMMON_SERVICES.keys())
    open_ports: List[PortResult] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {
            executor.submit(scan_port, host, port, timeout, grab_banner): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result.open:
                open_ports.append(result)

    return sorted(open_ports, key=lambda r: r.port)
