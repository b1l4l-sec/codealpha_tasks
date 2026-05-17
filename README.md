# CodeAlpha Cybersecurity Internship

**Intern:** LBIEN Bilal | github.com/b1l4l-sec | ENSA Fes — GDNC
**Student ID:** CA/DF1/55893
**Domain:** Cyber Security
**Duration:** 1st May 2026 — 30th May 2026

---

## Completed Tasks

### Task 1 — Basic Network Sniffer
**Folder:** `CodeAlpha_NetworkSniffer/`

A multi-layer Python network packet sniffer built with Scapy.
Captures and analyzes live network traffic with deep protocol dissection across Ethernet, IP, TCP/UDP, and application layers.

**Features:**
- 30+ protocols identified by port mapping
- TLS handshake detection (ClientHello, ServerHello)
- DNS query/response parsing with resolved IPs
- HTTP method, host, path and status code extraction
- Cleartext protocol warnings (TELNET, FTP)
- ARP spoofing monitoring
- Colored terminal output with live statistics
- BPF filter support and interface selection

**Stack:** Python · Scapy · Colorama

    sudo python3 sniffer.py -i enp0s3 -c 50
    sudo python3 sniffer.py -f "udp port 53"

---

### Task 3 — Secure Coding Review
**Folder:** `CodeAlpha_SecureCodeReview/`

A full security audit cycle: built a vulnerable Flask app, audited it with Bandit static analysis and manual review, exploited 7 vulnerabilities live, then developed a fully remediated secure version.

**Vulnerabilities Found & Fixed:**

| # | Vulnerability | Severity | OWASP | Status |
|---|--------------|----------|-------|--------|
| 1 | SQL Injection | HIGH | A03 | Fixed |
| 2 | Command Injection | HIGH | A03 | Fixed |
| 3 | Cross-Site Scripting (XSS) | MEDIUM | A03 | Fixed |
| 4 | Hardcoded Secret Key | MEDIUM | A02 | Fixed |
| 5 | Path Traversal (File Upload) | MEDIUM | A01 | Fixed |
| 6 | Plaintext Password Storage | LOW | A02 | Fixed |
| 7 | Debug Mode + Open Bind | HIGH | A05 | Fixed |

**Stack:** Python · Flask · Bandit · OWASP Top 10

    cd CodeAlpha_SecureCodeReview/vulnerable && python3 app.py
    cd CodeAlpha_SecureCodeReview/secure && python3 app.py

---

### Task 4 — Network Intrusion Detection System
**Folder:** `CodeAlpha_NIDS/`

A production-grade rule-based NIDS with 10 detection rules, sliding window algorithm, per-IP state tracking, real-time web dashboard, and Rich terminal dashboard. Tested with real attacks from Kali Linux.

**Detection Rules:**

| Rule | Severity | Method |
|------|----------|--------|
| Port Scan | HIGH | Sliding window — distinct ports per IP |
| SYN Flood | HIGH | Sliding window — SYN rate per IP |
| ICMP Flood | MEDIUM | Sliding window — ICMP rate per IP |
| Brute Force | CRITICAL | Connection attempts to sensitive ports |
| ARP Spoofing | CRITICAL | MAC address change detection |
| NULL Scan | MEDIUM | TCP flag inspection |
| FIN Scan | MEDIUM | TCP flag inspection |
| XMAS Scan | MEDIUM | TCP flag inspection |
| DNS Amplification | HIGH | Oversized DNS response detection |
| Suspicious Payload | HIGH | Signature matching (SQLi/XSS/LFI/CMDi) |

**Stack:** Python · Scapy · Flask · Rich · Chart.js

    python3 nids.py --demo --web
    sudo python3 nids.py --live --iface enp0s3 --web
    sudo python3 nids.py --live --iface enp0s3 --dashboard

---

## Repository Structure

    CodeAlpha/
    |-- CodeAlpha_NetworkSniffer/     Task 1
    |   |-- sniffer.py
    |   |-- packet_analyzer.py
    |   |-- display.py
    |   └-- README.md
    |-- CodeAlpha_SecureCodeReview/   Task 3
    |   |-- vulnerable/app.py
    |   |-- secure/app.py
    |   |-- AUDIT_REPORT.md
    |   └-- README.md
    └-- CodeAlpha_NIDS/               Task 4
        |-- nids.py
        |-- detector.py
        |-- sniffer.py
        |-- display.py
        |-- dashboard_web.py
        |-- templates/dashboard.html
        └-- README.md

---

## Tech Stack Overview

| Technology | Usage |
|------------|-------|
| Python 3.12 | Core language for all tasks |
| Scapy | Packet capture and protocol dissection |
| Flask | Web dashboards and REST APIs |
| Rich | Terminal UI and live dashboards |
| Chart.js | Web dashboard data visualization |
| Bandit | Static security analysis |
| Nmap / hping3 | Attack simulation and testing |
| Kali Linux | Penetration testing platform |

---

## Legal Notice

All projects are developed strictly for educational purposes as part of the CodeAlpha Cybersecurity Internship. Offensive tools and techniques demonstrated here must only be used on networks and systems you own or have explicit permission to test.

---

*CodeAlpha Cybersecurity Internship — May 2026*
*LBIEN Bilal | ENSA Fes | github.com/b1l4l-sec*
