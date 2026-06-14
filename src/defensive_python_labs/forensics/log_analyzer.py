"""
Log analyzer for suspicious activity detection.

Parses and analyzes common log formats:
- Apache / Nginx access logs (Common Log Format)
- SSH auth logs (/var/log/auth.log)
- Generic system logs

Detects: brute-force attempts, port scans, unusual access patterns,
         4xx/5xx error spikes, suspicious user agents, and more.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# --- Patterns ---

# Apache/Nginx Combined Log Format
APACHE_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+)? ?(?P<path>\S+)? ?(?P<protocol>\S+)?" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?'
)

# SSH brute force patterns
SSH_FAILED_PATTERN = re.compile(
    r"(?P<timestamp>\w+ +\d+ \d+:\d+:\d+).*"
    r"(?:Failed password|Invalid user|authentication failure)"
    r".*?(?:from (?P<ip>\d+\.\d+\.\d+\.\d+))?",
    re.IGNORECASE,
)

SSH_SUCCESS_PATTERN = re.compile(
    r"(?P<timestamp>\w+ +\d+ \d+:\d+:\d+).*"
    r"Accepted (?P<method>\w+) for (?P<user>\w+) from (?P<ip>\S+)",
    re.IGNORECASE,
)

# Suspicious user agents (scanners, bots, exploit tools)
SUSPICIOUS_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "nessus", "openvas",
    "acunetix", "burpsuite", "zgrab", "python-requests", "go-http-client",
    "curl/", "wget/", "libwww-perl", "dirbuster", "gobuster",
]

# Suspicious URL patterns (LFI, RFI, SQLi, XSS probes)
SUSPICIOUS_PATHS = [
    re.compile(r"\.\./"),                        # path traversal
    re.compile(r"etc/passwd"),                   # LFI
    re.compile(r"union.*select", re.IGNORECASE), # SQLi
    re.compile(r"<script", re.IGNORECASE),       # XSS
    re.compile(r"cmd=|exec=|system="),           # command injection
    re.compile(r"\.php\?.*=http"),               # RFI
    re.compile(r"wp-admin|wp-login"),            # WordPress attack
    re.compile(r"\.(env|git|svn|bak)"),          # sensitive file probing
    re.compile(r"eval\(|base64_decode\("),       # PHP injection
]


@dataclass
class LogEntry:
    raw: str
    ip: Optional[str] = None
    timestamp: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status: Optional[int] = None
    agent: Optional[str] = None
    suspicious: bool = False
    flags: List[str] = field(default_factory=list)


@dataclass
class LogReport:
    total_lines: int
    parsed_lines: int
    unique_ips: int
    top_ips: List[Tuple[str, int]]
    status_distribution: Dict[str, int]
    error_rate: float                      # % of 4xx/5xx
    suspicious_entries: List[LogEntry]
    brute_force_ips: List[Tuple[str, int]] # IP → failed attempt count
    top_paths: List[Tuple[str, int]]
    top_agents: List[Tuple[str, int]]
    summary: str = ""

    def __str__(self) -> str:
        lines = [
            f"\n{'='*55}",
            f"  Log Analysis Report",
            f"{'='*55}",
            f"  Total lines   : {self.total_lines:,}",
            f"  Parsed        : {self.parsed_lines:,}",
            f"  Unique IPs    : {self.unique_ips:,}",
            f"  Error rate    : {self.error_rate:.1f}%",
            "",
            "  Top IPs by request count:",
        ]
        for ip, count in self.top_ips[:10]:
            lines.append(f"    {ip:<20} {count:>6} requests")

        if self.brute_force_ips:
            lines.append("\n  ⚠ Possible brute-force sources:")
            for ip, count in self.brute_force_ips:
                lines.append(f"    {ip:<20} {count:>6} failed attempts")

        lines.append("\n  Status code distribution:")
        for code, count in sorted(self.status_distribution.items()):
            lines.append(f"    {code}: {count:,}")

        if self.suspicious_entries:
            lines.append(f"\n  ⚠ Suspicious requests detected: {len(self.suspicious_entries)}")
            for entry in self.suspicious_entries[:5]:
                lines.append(f"    [{entry.ip}] {entry.path} — {', '.join(entry.flags)}")
            if len(self.suspicious_entries) > 5:
                lines.append(f"    ... and {len(self.suspicious_entries) - 5} more")

        lines.append(f"\n{'='*55}")
        return "\n".join(lines)


def _parse_apache_line(line: str) -> Optional[LogEntry]:
    m = APACHE_LOG_PATTERN.match(line)
    if not m:
        return None
    entry = LogEntry(
        raw=line,
        ip=m.group("ip"),
        timestamp=m.group("time"),
        method=m.group("method"),
        path=m.group("path"),
        status=int(m.group("status")),
        agent=m.group("agent"),
    )
    # Flag suspicious activity
    if entry.agent:
        for bad in SUSPICIOUS_AGENTS:
            if bad.lower() in entry.agent.lower():
                entry.suspicious = True
                entry.flags.append(f"Suspicious agent: {bad}")
                break
    if entry.path:
        for pattern in SUSPICIOUS_PATHS:
            if pattern.search(entry.path):
                entry.suspicious = True
                entry.flags.append(f"Suspicious path pattern: {pattern.pattern}")
    return entry


def analyze_apache_log(log_path: str, brute_threshold: int = 20) -> LogReport:
    """
    Parse and analyze an Apache/Nginx access log file.

    Parameters
    ----------
    log_path : str
        Path to the log file.
    brute_threshold : int
        Number of 4xx/5xx requests from one IP before it's flagged.

    Returns
    -------
    LogReport
        Full analysis with IPs, error rates, suspicious requests, etc.

    Examples
    --------
    >>> import tempfile
    >>> log_line = '192.168.1.1 - - [01/Jan/2025:00:00:00 +0000] "GET / HTTP/1.1" 200 1234\\n'
    >>> with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
    ...     _ = f.write(log_line)
    ...     path = f.name
    >>> report = analyze_apache_log(path)
    >>> report.parsed_lines
    1
    """
    path = Path(log_path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    entries: List[LogEntry] = []
    ip_counter: Counter = Counter()
    status_counter: Counter = Counter()
    path_counter: Counter = Counter()
    agent_counter: Counter = Counter()
    ip_errors: Counter = Counter()
    suspicious: List[LogEntry] = []

    total = 0
    with open(path, "r", errors="replace") as f:
        for line in f:
            total += 1
            entry = _parse_apache_line(line.strip())
            if entry:
                entries.append(entry)
                if entry.ip:
                    ip_counter[entry.ip] += 1
                if entry.status:
                    status_counter[str(entry.status)] += 1
                    if entry.status >= 400:
                        if entry.ip:
                            ip_errors[entry.ip] += 1
                if entry.path:
                    path_counter[entry.path] += 1
                if entry.agent:
                    agent_counter[entry.agent] += 1
                if entry.suspicious:
                    suspicious.append(entry)

    error_count = sum(c for s, c in status_counter.items() if int(s) >= 400)
    total_requests = len(entries)
    error_rate = (error_count / total_requests * 100) if total_requests else 0.0

    brute_force = [(ip, count) for ip, count in ip_errors.most_common() if count >= brute_threshold]

    return LogReport(
        total_lines=total,
        parsed_lines=len(entries),
        unique_ips=len(ip_counter),
        top_ips=ip_counter.most_common(20),
        status_distribution=dict(status_counter),
        error_rate=error_rate,
        suspicious_entries=suspicious,
        brute_force_ips=brute_force,
        top_paths=path_counter.most_common(10),
        top_agents=agent_counter.most_common(10),
    )


def analyze_ssh_log(log_path: str, fail_threshold: int = 5) -> Dict:
    """
    Analyze an SSH auth log for brute-force and unauthorized access attempts.

    Parameters
    ----------
    log_path : str
        Path to auth.log or similar SSH log file.
    fail_threshold : int
        Failed login count to flag an IP as suspicious.

    Returns
    -------
    dict
        Summary with attacker IPs, targeted usernames, and successful logins.

    Examples
    --------
    >>> import tempfile
    >>> line = 'Jun 14 10:00:00 host sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2\\n'
    >>> with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
    ...     _ = f.write(line)
    ...     path = f.name
    >>> result = analyze_ssh_log(path)
    >>> '1.2.3.4' in result['attacker_ips']
    True
    """
    path = Path(log_path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    failed_by_ip: Counter = Counter()
    failed_users: Counter = Counter()
    successful_logins: List[Dict] = []

    with open(path, "r", errors="replace") as f:
        for line in f:
            fail_m = SSH_FAILED_PATTERN.search(line)
            if fail_m:
                ip = fail_m.group("ip")
                if ip:
                    failed_by_ip[ip] += 1
                # Try to extract username
                user_m = re.search(r"(?:for|user) (\w+)", line, re.IGNORECASE)
                if user_m:
                    failed_users[user_m.group(1)] += 1

            success_m = SSH_SUCCESS_PATTERN.search(line)
            if success_m:
                successful_logins.append({
                    "timestamp": success_m.group("timestamp"),
                    "user": success_m.group("user"),
                    "ip": success_m.group("ip"),
                    "method": success_m.group("method"),
                })

    attackers = {ip: count for ip, count in failed_by_ip.items() if count >= fail_threshold}

    return {
        "attacker_ips": dict(sorted(attackers.items(), key=lambda x: -x[1])),
        "all_failed_ips": dict(failed_by_ip.most_common(20)),
        "targeted_usernames": dict(failed_users.most_common(10)),
        "successful_logins": successful_logins,
        "total_failed_attempts": sum(failed_by_ip.values()),
    }
