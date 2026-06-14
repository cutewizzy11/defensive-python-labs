# defensive-python-labs 🛡️

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Educational](https://img.shields.io/badge/purpose-educational-orange.svg)](#disclaimer)

> **Educational Python labs and utilities for defensive cybersecurity.**
> Learn real-world security concepts through hands-on Python code — no prior security experience needed.

---

## What is this?

`defensive-python-labs` is a growing toolkit of **pure-Python security utilities** that you can use to:

- **Learn** how common attacks work (so you can defend against them)
- **Audit** your own systems, websites, and files
- **Practice** cybersecurity concepts in a safe, legal environment
- **Teach** security fundamentals with working, readable code

Every module is **self-contained**, **well-documented**, and designed to run with minimal dependencies.

---

## 🚀 Quick Start

```bash
git clone https://github.com/cutewizzy11/defensive-python-labs.git
cd defensive-python-labs
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

Now you have the `dplabs` command:

```bash
dplabs --help
```

---

## 🧰 Modules

### 🔍 Recon

**Port Scanner** — Threaded TCP scanner with banner grabbing and service detection.

```bash
# Scan common ports (fast)
dplabs portscan example.com --common --banner

# Scan a custom range
dplabs portscan 192.168.1.1 --start 1 --end 65535
```

```
PORT     SERVICE         BANNER
────────────────────────────────────────────────────────────
22       SSH             SSH-2.0-OpenSSH_8.9p1
80       HTTP            HTTP/1.1 301 Moved Permanently
443      HTTPS
3306     MySQL

[+] 4 open port(s) found on example.com
```

**DNS Recon** — Subdomain enumeration and reverse DNS lookups.

```bash
dplabs dns example.com --subdomains
dplabs dns 8.8.8.8 --reverse
```

---

### 🔐 Password Security

**Password Strength Analyzer** — Entropy-based analysis with actionable feedback.

```bash
dplabs password --password "MyS3cur3P@ss!"
dplabs password --file passwords.txt        # audit a list
```

```
Password : *************
Strength : Strong  (score 78/100)
Entropy  : 72.4 bits
Tips     :
  • Aim for 16+ characters for better security.
  • Add at least one special character (!@#$%^&*).
```

**Hash Cracker (Educational Demo)** — See WHY unsalted MD5 is broken in seconds.

```bash
# Dictionary attack
dplabs crack 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist rockyou.txt

# Brute force (short passwords only — proves the point)
dplabs crack 900150983cd24fb0d6963f7d28e17f72 --algorithm md5
```

```
Algorithm : MD5
Result    : ✓ CRACKED: 'abc'
Attempts  : 3
Time      : 0.001s
```

> This demonstrates in real time why `md5(password)` without a salt is dangerously weak.

---

### 🌐 Web Security

**HTTP Security Headers Analyzer** — Grade any website's security posture in seconds.

```bash
dplabs headers https://yourwebsite.com
```

```
═══════════════════════════════════════════════════════
  Security Headers Report
  URL   : https://yourwebsite.com
  Score : 42/100   Grade: D
═══════════════════════════════════════════════════════

✗ Missing headers:
  [C] Content-Security-Policy
     → Prevents XSS and data injection attacks. Set to: default-src 'self'
  [C] Strict-Transport-Security
     → Forces browsers to use HTTPS. Set to: max-age=31536000; includeSubDomains
  [H] X-Frame-Options
     → Prevents clickjacking. Set to: DENY or SAMEORIGIN

⚠  Information-leaking headers found:
  • X-Powered-By: PHP/8.1.2 — remove or obscure this header
```

Use this against **your own site** before an attacker does.

---

### 🔬 Forensics

**File Metadata Extractor** — Hashes, timestamps, EXIF data, type detection, anomaly flags.

```bash
dplabs metadata suspicious_image.jpg
```

```
──────────────────────────────────────────────────
  File Metadata Report
  File    : suspicious_image.jpg
  Size    : 2,048,312 bytes (2000.3 KB)
  Type    : JPEG Image (image/jpeg)
  MD5     : d41d8cd98f00b204e9800998ecf8427e
  SHA256  : e3b0c44298fc1c149afbf4c8996fb92427ae41...
──────────────────────────────────────────────────
  GPS: {'GPSLatitude': (40, 42, 46.0), 'GPSLongitude': (74, 0, 21.0)}
  Make: Apple
  Model: iPhone 14 Pro

⚠ Anomalies detected:
  • File was modified less than 24 hours ago
```

**Log Analyzer** — Detect brute-force attacks, port scans, and web exploits in your logs.

```bash
dplabs logs /var/log/apache2/access.log --type apache
dplabs logs /var/log/auth.log --type ssh
```

```
  ⚠ Possible brute-force sources:
    185.220.101.42       4,821 requests
    45.33.32.156           312 requests

  ⚠ Suspicious requests detected: 47
    [185.220.101.42] /admin.php?cmd=whoami — Suspicious path pattern
    [185.220.101.42] /../../../etc/passwd — path traversal
```

---

### 🦠 Malware Analysis (Static)

Analyze suspicious files **without running them**.

```bash
dplabs malware suspicious.exe
```

```
══════════════════════════════════════════════════════════
  Static Malware Analysis Report
  File      : suspicious.exe
  Size      : 245,760 bytes
══════════════════════════════════════════════════════════
  MD5    : 1f3870be274f6c49b3e31a0c6728957f
  SHA256 : 2c624232cdd221771294dfbb310acbc...

  Entropy   : 7.82 / 8.0  [VERY HIGH — likely packed/encrypted]
  Risk      : HIGH RISK — manual review strongly recommended  (85/100)

  ⚠ Suspicious strings (12):
    • CreateRemoteThread
    • VirtualAllocEx
    • cmd.exe /c whoami

  Indicators of Compromise (IOCs):
    URL:
      - http://evil-c2.example.com/shell
    IPv4:
      - 185.220.101.42
```

---

## 📁 Project Structure

```
src/defensive_python_labs/
├── recon/
│   ├── port_scanner.py       # Threaded TCP scanner + banner grabbing
│   └── dns_recon.py          # Subdomain enum, reverse DNS
├── crypto/
│   └── classic_ciphers.py    # Caesar, Vigenère (educational)
├── forensics/
│   ├── metadata_extractor.py # File hashes, EXIF, anomaly detection
│   └── log_analyzer.py       # Apache/SSH log analysis
├── password_security/
│   ├── password_strength.py  # Entropy-based strength analyzer
│   └── hash_cracker.py       # Dictionary + brute force demo
├── malware_analysis/
│   └── static_analyzer.py    # Entropy, strings, IOC extraction
└── cli.py                    # Unified CLI entry point
```

---

## 🎓 Who is this for?

| You are... | How to use this |
|---|---|
| **Beginners** learning cybersecurity | Read each module top-to-bottom — they're heavily commented |
| **Developers** building secure apps | Use `headers_analyzer` against your app; use `password_strength` in your backend |
| **Students** in security courses | Run the labs, modify the code, write your own modules |
| **Sysadmins** | Drop `log_analyzer` on your access logs right now |
| **CTF players** | The crypto and forensics modules have obvious applications |

---

## 🤝 Contributing

Contributions are **very welcome** — this project grows by community additions.

Ideas for new labs:
- **Network**: ARP spoofing detector, PCAP analyzer
- **Web**: SQL injection scanner (on your own sites), CORS misconfiguration checker  
- **Crypto**: RSA key size checker, TLS cipher suite auditor
- **Forensics**: Memory dump string extractor, registry hive reader
- **Threat Intel**: IOC checker against AbuseIPDB, VirusTotal API wrapper

See [CONTRIBUTING.md](CONTRIBUTING.md) — we label good starter issues with `good first issue`.

---

## ⚠️ Disclaimer

This project is for **educational and defensive purposes only**.

**Do not** use any tool in this repository against systems, networks, or accounts you do not own or have explicit written permission to test. Unauthorized scanning and testing is **illegal** in most jurisdictions.

---

## 📄 License

MIT © [Paul Anyebe](https://github.com/cutewizzy11)
