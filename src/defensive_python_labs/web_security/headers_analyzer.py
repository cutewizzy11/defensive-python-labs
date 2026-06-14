"""
HTTP Security Headers Analyzer.

Checks a website's response headers against modern security best practices.
No external dependencies — uses only the standard library.

This is one of the most practically useful tools in this lab:
every web developer and sysadmin should run this against their own sites.
"""

from __future__ import annotations

import ssl
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Header name → (description, why it matters, example good value)
SECURITY_HEADERS: Dict[str, Tuple[str, str, str]] = {
    "Strict-Transport-Security": (
        "HTTP Strict Transport Security (HSTS)",
        "Forces browsers to use HTTPS. Prevents SSL stripping attacks.",
        "max-age=31536000; includeSubDomains; preload",
    ),
    "Content-Security-Policy": (
        "Content Security Policy (CSP)",
        "Prevents XSS and data injection attacks by whitelisting content sources.",
        "default-src 'self'; script-src 'self'",
    ),
    "X-Frame-Options": (
        "X-Frame-Options",
        "Prevents your site from being embedded in iframes (clickjacking defence).",
        "DENY or SAMEORIGIN",
    ),
    "X-Content-Type-Options": (
        "X-Content-Type-Options",
        "Stops browsers from MIME-sniffing — prevents drive-by downloads.",
        "nosniff",
    ),
    "Referrer-Policy": (
        "Referrer-Policy",
        "Controls how much referrer info is sent with requests.",
        "strict-origin-when-cross-origin",
    ),
    "Permissions-Policy": (
        "Permissions-Policy",
        "Controls browser features (camera, mic, location) accessible to the page.",
        "camera=(), microphone=(), geolocation=()",
    ),
    "X-XSS-Protection": (
        "X-XSS-Protection",
        "Legacy XSS filter for older browsers (CSP supersedes this).",
        "1; mode=block",
    ),
    "Cross-Origin-Opener-Policy": (
        "Cross-Origin-Opener-Policy (COOP)",
        "Isolates browsing context — mitigates Spectre-style side-channel attacks.",
        "same-origin",
    ),
    "Cross-Origin-Resource-Policy": (
        "Cross-Origin-Resource-Policy (CORP)",
        "Prevents other origins from loading your resources.",
        "same-site",
    ),
}

# Headers that expose too much info
INFORMATION_LEAKING_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


@dataclass
class HeaderCheck:
    name: str
    present: bool
    value: Optional[str]
    description: str
    recommendation: str
    severity: str  # "critical" | "high" | "medium" | "info"


@dataclass
class HeadersReport:
    url: str
    score: int                            # 0–100
    grade: str                            # A+ / A / B / C / D / F
    checks: List[HeaderCheck] = field(default_factory=list)
    leaking_headers: List[str] = field(default_factory=list)
    raw_headers: Dict[str, str] = field(default_factory=dict)

    def __str__(self) -> str:
        lines = [
            f"\n{'='*55}",
            f"  Security Headers Report",
            f"  URL   : {self.url}",
            f"  Score : {self.score}/100   Grade: {self.grade}",
            f"{'='*55}",
        ]
        missing = [c for c in self.checks if not c.present]
        present = [c for c in self.checks if c.present]

        if present:
            lines.append("\n✓ Present headers:")
            for c in present:
                lines.append(f"  [{c.severity.upper()[:1]}] {c.name}: {c.value}")

        if missing:
            lines.append("\n✗ Missing headers:")
            for c in missing:
                lines.append(f"  [{c.severity.upper()[:1]}] {c.name}")
                lines.append(f"     → {c.recommendation}")

        if self.leaking_headers:
            lines.append("\n⚠  Information-leaking headers found:")
            for h in self.leaking_headers:
                lines.append(f"  • {h} — remove or obscure this header")

        return "\n".join(lines)


def _severity(header: str) -> str:
    critical = {"Content-Security-Policy", "Strict-Transport-Security"}
    high = {"X-Frame-Options", "X-Content-Type-Options"}
    if header in critical:
        return "critical"
    if header in high:
        return "high"
    return "medium"


def analyze_url(url: str, timeout: int = 10) -> HeadersReport:
    """
    Fetch a URL and analyze its HTTP security headers.

    Parameters
    ----------
    url : str
        Full URL including scheme, e.g. "https://example.com".
    timeout : int
        Request timeout in seconds.

    Returns
    -------
    HeadersReport
        Detailed report with score, grade, and per-header findings.

    Examples
    --------
    >>> report = analyze_url("https://example.com")
    >>> isinstance(report.score, int)
    True
    >>> 0 <= report.score <= 100
    True
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Fetch headers (skip cert verification for educational scanning only)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    raw: Dict[str, str] = {}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "defensive-python-labs/1.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
            for key, value in response.headers.items():
                raw[key] = value
    except urllib.error.URLError as exc:
        raise ConnectionError(f"Could not reach {url}: {exc}") from exc

    # Build checks
    checks: List[HeaderCheck] = []
    missing_count = 0

    for header_name, (description, reason, example) in SECURITY_HEADERS.items():
        # Case-insensitive header lookup
        value = next((v for k, v in raw.items() if k.lower() == header_name.lower()), None)
        present = value is not None
        if not present:
            missing_count += 1

        checks.append(HeaderCheck(
            name=header_name,
            present=present,
            value=value,
            description=description,
            recommendation=f"{reason} Set to: {example}",
            severity=_severity(header_name),
        ))

    # Information leaking headers
    leaking = [
        f"{k}: {v}" for k, v in raw.items()
        if any(k.lower() == lh.lower() for lh in INFORMATION_LEAKING_HEADERS)
    ]

    # Score: each missing header deducts points; critical ones count double
    total_headers = len(SECURITY_HEADERS)
    score = 100
    for check in checks:
        if not check.present:
            deduction = 15 if check.severity == "critical" else 10 if check.severity == "high" else 6
            score -= deduction
    score -= len(leaking) * 3
    score = max(0, min(100, score))

    grade = "A+" if score >= 95 else "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 55 else "D" if score >= 40 else "F"

    return HeadersReport(
        url=url,
        score=score,
        grade=grade,
        checks=checks,
        leaking_headers=leaking,
        raw_headers=raw,
    )


def analyze_headers_dict(headers: Dict[str, str], url: str = "N/A") -> HeadersReport:
    """
    Analyze a dict of headers directly (useful for testing without a live URL).

    Examples
    --------
    >>> report = analyze_headers_dict({"X-Frame-Options": "DENY"})
    >>> any(c.present for c in report.checks if c.name == "X-Frame-Options")
    True
    """
    checks: List[HeaderCheck] = []
    for header_name, (description, reason, example) in SECURITY_HEADERS.items():
        value = next((v for k, v in headers.items() if k.lower() == header_name.lower()), None)
        checks.append(HeaderCheck(
            name=header_name,
            present=value is not None,
            value=value,
            description=description,
            recommendation=f"{reason} Set to: {example}",
            severity=_severity(header_name),
        ))

    leaking = [
        f"{k}: {v}" for k, v in headers.items()
        if any(k.lower() == lh.lower() for lh in INFORMATION_LEAKING_HEADERS)
    ]

    score = 100
    for check in checks:
        if not check.present:
            deduction = 15 if check.severity == "critical" else 10 if check.severity == "high" else 6
            score -= deduction
    score -= len(leaking) * 3
    score = max(0, min(100, score))
    grade = "A+" if score >= 95 else "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 55 else "D" if score >= 40 else "F"

    return HeadersReport(url=url, score=score, grade=grade, checks=checks, leaking_headers=leaking, raw_headers=headers)
