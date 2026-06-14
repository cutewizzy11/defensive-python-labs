#!/usr/bin/env python3
"""
defensive-python-labs CLI

A unified command-line interface for all defensive security labs.
Run any tool directly from your terminal.

Usage:
    python -m defensive_python_labs.cli <command> [options]

Or after install:
    dplabs <command> [options]
"""

from __future__ import annotations

import argparse
import sys
import textwrap


BANNER = r"""
 ██████╗ ███████╗███████╗███████╗███╗   ██╗███████╗██╗██╗   ██╗███████╗
 ██╔══██╗██╔════╝██╔════╝██╔════╝████╗  ██║██╔════╝██║██║   ██║██╔════╝
 ██║  ██║█████╗  █████╗  █████╗  ██╔██╗ ██║███████╗██║██║   ██║█████╗
 ██║  ██║██╔══╝  ██╔══╝  ██╔══╝  ██║╚██╗██║╚════██║██║╚██╗ ██╔╝██╔══╝
 ██████╔╝███████╗██║     ███████╗██║ ╚████║███████║██║ ╚████╔╝ ███████╗
 ╚═════╝ ╚══════╝╚═╝     ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═══╝  ╚══════╝
  Python Labs — Educational Defensive Cybersecurity Toolkit
"""


# ── Port Scanner ─────────────────────────────────────────────────────────────

def cmd_portscan(args: argparse.Namespace) -> None:
    from defensive_python_labs.recon.port_scanner import scan_range, scan_common_ports

    print(f"\n[*] Scanning {args.host} ...")
    if args.common:
        results = scan_common_ports(args.host, grab_banner=args.banner)
    else:
        results = scan_range(
            args.host, args.start, args.end,
            timeout=args.timeout, grab_banner=args.banner,
        )

    if not results:
        print("[!] No open ports found.")
        return

    print(f"\n{'PORT':<8} {'SERVICE':<15} {'BANNER'}")
    print("─" * 60)
    for r in results:
        print(f"{r.port:<8} {r.service:<15} {r.banner[:40] if r.banner else ''}")
    print(f"\n[+] {len(results)} open port(s) found on {args.host}")


# ── DNS Recon ────────────────────────────────────────────────────────────────

def cmd_dns(args: argparse.Namespace) -> None:
    from defensive_python_labs.recon.dns_recon import resolve, reverse_lookup, enumerate_subdomains

    if args.reverse:
        hostname = reverse_lookup(args.target)
        print(f"\n[+] Reverse lookup for {args.target}: {hostname or 'No result'}")
        return

    if args.subdomains:
        print(f"\n[*] Enumerating subdomains for {args.target} ...")
        records = enumerate_subdomains(args.target)
        if not records:
            print("[!] No subdomains found.")
        for r in records:
            print(f"  {r.subdomain:<40} {r.ip}")
        print(f"\n[+] {len(records)} subdomain(s) found.")
        return

    ip = resolve(args.target)
    print(f"\n[+] {args.target} → {ip or 'Could not resolve'}")


# ── Password Analyzer ────────────────────────────────────────────────────────

def cmd_password(args: argparse.Namespace) -> None:
    from defensive_python_labs.password_security.password_strength import analyze, bulk_analyze

    if args.file:
        with open(args.file) as f:
            passwords = [line.strip() for line in f if line.strip()]
        reports = bulk_analyze(passwords)
        print(f"\n[*] Analyzed {len(reports)} password(s) — sorted weakest first:\n")
        for r in reports:
            bar = "█" * (r.score // 10) + "░" * (10 - r.score // 10)
            print(f"  {'*'*len(r.password):<20} [{bar}] {r.strength} ({r.score}/100)")
    else:
        report = analyze(args.password)
        print(report)


# ── Hash Cracker ─────────────────────────────────────────────────────────────

def cmd_crack(args: argparse.Namespace) -> None:
    from defensive_python_labs.password_security.hash_cracker import (
        dictionary_attack, brute_force, identify_hash
    )

    possible = identify_hash(args.hash)
    algo = args.algorithm or (possible[0] if possible else "md5")
    print(f"\n[*] Target hash : {args.hash}")
    print(f"[*] Algorithm   : {algo.upper()} (detected: {', '.join(possible)})")

    if args.wordlist:
        with open(args.wordlist) as f:
            words = [line.strip() for line in f if line.strip()]
        print(f"[*] Wordlist    : {args.wordlist} ({len(words):,} words)")
        result = dictionary_attack(args.hash, algo, words)
    else:
        print("[*] Mode        : Brute force (max length 5)")
        result = brute_force(args.hash, algo, max_length=5)

    print(result)


# ── Headers Analyzer ─────────────────────────────────────────────────────────

def cmd_headers(args: argparse.Namespace) -> None:
    from defensive_python_labs.web_security.headers_analyzer import analyze_url

    print(f"\n[*] Checking security headers for {args.url} ...")
    try:
        report = analyze_url(args.url)
        print(report)
    except ConnectionError as e:
        print(f"[!] {e}")


# ── Forensics: File Metadata ──────────────────────────────────────────────────

def cmd_metadata(args: argparse.Namespace) -> None:
    from defensive_python_labs.forensics.metadata_extractor import extract

    try:
        meta = extract(args.file)
        print(meta)
    except FileNotFoundError as e:
        print(f"[!] {e}")


# ── Forensics: Log Analyzer ───────────────────────────────────────────────────

def cmd_logs(args: argparse.Namespace) -> None:
    if args.type == "apache":
        from defensive_python_labs.forensics.log_analyzer import analyze_apache_log
        report = analyze_apache_log(args.file)
        print(report)
    elif args.type == "ssh":
        from defensive_python_labs.forensics.log_analyzer import analyze_ssh_log
        result = analyze_ssh_log(args.file)
        print(f"\n[+] SSH Log Analysis: {args.file}")
        print(f"  Total failed attempts : {result['total_failed_attempts']:,}")
        print(f"\n  Top attacker IPs:")
        for ip, count in list(result["attacker_ips"].items())[:10]:
            print(f"    {ip:<20} {count:>6} failures")
        print(f"\n  Most targeted usernames:")
        for user, count in list(result["targeted_usernames"].items())[:10]:
            print(f"    {user:<20} {count:>6} attempts")
        if result["successful_logins"]:
            print(f"\n  ⚠ Successful logins ({len(result['successful_logins'])}):")
            for login in result["successful_logins"]:
                print(f"    {login['timestamp']}  {login['user']}@{login['ip']} via {login['method']}")


# ── Static Malware Analysis ───────────────────────────────────────────────────

def cmd_malware(args: argparse.Namespace) -> None:
    from defensive_python_labs.malware_analysis.static_analyzer import analyze

    print(f"\n[*] Running static analysis on: {args.file}")
    try:
        report = analyze(args.file)
        print(report)
    except FileNotFoundError as e:
        print(f"[!] {e}")


# ── Main ──────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dplabs",
        description="Defensive Python Labs — Educational Cybersecurity Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              dplabs portscan example.com --common --banner
              dplabs dns example.com --subdomains
              dplabs password --password "P@ssw0rd"
              dplabs crack 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist rockyou.txt
              dplabs headers https://example.com
              dplabs metadata suspicious_file.exe
              dplabs logs --type apache /var/log/apache2/access.log
              dplabs malware suspicious.exe
        """),
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    # portscan
    ps = sub.add_parser("portscan", help="TCP port scanner with banner grabbing")
    ps.add_argument("host", help="Target host (IP or domain)")
    ps.add_argument("--start", type=int, default=1, help="Start port (default: 1)")
    ps.add_argument("--end", type=int, default=1024, help="End port (default: 1024)")
    ps.add_argument("--timeout", type=float, default=1.0, help="Connection timeout (default: 1.0)")
    ps.add_argument("--common", action="store_true", help="Scan well-known ports only (faster)")
    ps.add_argument("--banner", action="store_true", help="Attempt banner grabbing")
    ps.set_defaults(func=cmd_portscan)

    # dns
    dns = sub.add_parser("dns", help="DNS reconnaissance and subdomain enumeration")
    dns.add_argument("target", help="Domain or IP to investigate")
    dns.add_argument("--subdomains", action="store_true", help="Enumerate subdomains")
    dns.add_argument("--reverse", action="store_true", help="Reverse DNS lookup (IP → hostname)")
    dns.set_defaults(func=cmd_dns)

    # password
    pw = sub.add_parser("password", help="Password strength analyzer")
    pw_group = pw.add_mutually_exclusive_group(required=True)
    pw_group.add_argument("--password", help="Single password to analyze")
    pw_group.add_argument("--file", help="File with one password per line (bulk analysis)")
    pw.set_defaults(func=cmd_password)

    # crack
    cr = sub.add_parser("crack", help="Educational hash cracker (dictionary / brute force)")
    cr.add_argument("hash", help="Hash to crack (hex string)")
    cr.add_argument("--algorithm", help="Hash algorithm: md5, sha1, sha256, sha512")
    cr.add_argument("--wordlist", help="Path to wordlist file")
    cr.set_defaults(func=cmd_crack)

    # headers
    hd = sub.add_parser("headers", help="HTTP security headers analyzer")
    hd.add_argument("url", help="URL to analyze (e.g. https://example.com)")
    hd.set_defaults(func=cmd_headers)

    # metadata
    md = sub.add_parser("metadata", help="File metadata + forensics extractor")
    md.add_argument("file", help="Path to file to analyze")
    md.set_defaults(func=cmd_metadata)

    # logs
    lg = sub.add_parser("logs", help="Log file analyzer for suspicious activity")
    lg.add_argument("file", help="Path to log file")
    lg.add_argument("--type", choices=["apache", "ssh"], default="apache",
                    help="Log type: apache or ssh (default: apache)")
    lg.set_defaults(func=cmd_logs)

    # malware
    mw = sub.add_parser("malware", help="Static malware analysis (no execution needed)")
    mw.add_argument("file", help="Path to suspicious file")
    mw.set_defaults(func=cmd_malware)

    return parser


def main() -> None:
    print(BANNER)
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()
