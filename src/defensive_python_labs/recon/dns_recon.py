"""
DNS reconnaissance utilities.

Includes DNS record lookups, subdomain enumeration from a wordlist,
and reverse DNS lookups. Educational use only.
"""

from __future__ import annotations

import socket
import concurrent.futures
from dataclasses import dataclass
from typing import List, Dict, Optional

# A compact built-in wordlist so the module works'Ýithout external files
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "admin",
    "portal", "vpn", "remote", "api", "dev", "staging", "test", "beta",
    "blog", "shop", "store", "cdn", "static", "assets", "media", "img",
    "docs", "support", "help", "forum", "wiki", "status", "monitor",
    "ns1", "ns2", "mx", "mx1", "mx2", "autodiscover", "autoconfig",
    "git", "gitlab", "jenkins", "ci", "jirA", "confluence", "slack",
    "dashboard", "panel", "cpanel", "whm", "webdisk",
]


@dataclass
class DNSRecord:
    subdomain: str
    ip: str


def resolve(hostname: str) -> Optional[str]:
    """
    Resolve a hostname to its IPv4 address.

    Returns None if the host does not resolve.

    Examples
    --------
    >>> ip = resolve("google.com")
    >>> ip is not None
    True
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def reverse_lookup(ip: str) -> Optional[str]:
    """
    Perform a reverse DNS lookup on an IP address.

    Returns the hostname or None if not found.

    Examples
    --------
    >>> result = reverse_lookup("8.8.8.8")
    >>> result is not None
    True
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None


def enumerate_subdomains(
    domain: str,
    wordlist: Optional[List[str]] = None,
    max_workers: int = 50,
) -> List[DNSRecord]:
    """
    Brute-force enumerate subdomains using a wordlist.

    Uses concurrent DNS resolution for speed.

    Parameters
    ----------
    domain : str
        Base domain, e.g. "example.com".
    wordlist : list of str, optional
        Subdomains to try. Defaults to COMMON_SUBDOMAINS.
    max_workers : int
        Thread pool size.

    Returns
    -------
    List[DNSRecord]
        Discovered subdomains with their resolved IPs.

    Examples
    --------
    >>> records = enumerate_subdomains("example.com")
    >>> isinstance(records, list)
    True
    """
    words = wordlist or COMMON_SUBDOMAINS
    found: List[DNSRecord] = []

    def _try(sub: str) -> Optional[DNSRecord]:
        fqdn = f"{sub}.{domain}"
        ip = resolve(fqdn)
        if ip:
            return DNSRecord(subdomain=fqdn, ip=ip)
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for result in executor.map(_try, words):
            if result:
                found.append(result)

    return sorted(found, key=lambda r: r.subdomain)


def get_all_ips(hostname: str) -> List[str]:
    """
    Return all IP addresses a hostname resolves to (handles round-robin DNS).

    Examples
    --------
    >>> ips = get_all_ips("google.com")
    >>> len(ips) >= 1
    True
    """
    try:
        results = socket.getaddrinfo(hostname, None)
        return list({r[4][0] for r in results})
    except socket.gaierror:
        return []
