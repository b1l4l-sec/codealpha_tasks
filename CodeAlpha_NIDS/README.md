# CodeAlpha NIDS — Task 4: Network Intrusion Detection System

CodeAlpha Cybersecurity Internship — Task 4  
Author: LBIEN Bilal | github.com/b1l4l-sec | ENSA Fes — GDNC

---

## Overview

A production-grade rule-based Network Intrusion Detection System built in Python.
Supports both live packet capture (Scapy) and simulated attack traffic for demo/testing.
Features a real-time web dashboard and a Rich terminal dashboard.

---

## Detection Rules

| Rule | Severity | Description |
|------|----------|-------------|
| Port Scan | HIGH | Detects hosts probing multiple ports |
| SYN Flood | HIGH | Detects TCP SYN flood attacks |
| ICMP Flood | MEDIUM | Detects ICMP echo request floods |
| Brute Force | CRITICAL | Detects repeated auth attempts on SSH/RDP/FTP |
| ARP Spoofing | CRITICAL | Detects MAC address changes (MITM) |
| NULL Scan | MEDIUM | Detects TCP NULL scans |
| FIN Scan | MEDIUM | Detects TCP FIN scans |
| XMAS Scan | MEDIUM | Detects TCP XMAS scans |
| DNS Amplification | HIGH | Detects oversized DNS responses |
| Suspicious Payload | HIGH | Detects SQLi, XSS, LFI, CMDi in traffic |

---

## Architecture

    CodeAlpha_NIDS/
    |-- nids.py           # Main entry point — CLI, threading, orchestration
    |-- detector.py       # Detection engine — sliding window, 10 rules
    |-- sniffer.py        # LiveSniffer (Scapy) + SimulatedSniffer
    |-- display.py        # Rich terminal dashboard
    |-- dashboard_web.py  # Flask REST API + web dashboard server
    |-- templates/
    |   └── dashboard.html  # Real-time web dashboard (Chart.js)
    |-- logs/
    |   └── alerts.json   # Alert log output
    |-- requirements.txt

---

## Installation

    git clone https://github.com/b1l4l-sec/CodeAlpha.git
    cd CodeAlpha/CodeAlpha_NIDS
    sudo pip3 install -r requirements.txt --break-system-packages

---

## Usage

    # Demo mode (no root needed)
    python3 nids.py --demo --web

    # Live capture + web dashboard
    sudo python3 nids.py --live --iface enp0s3 --web

    # Terminal dashboard
    sudo python3 nids.py --live --iface enp0s3 --dashboard

    # List all options
    python3 nids.py --help

---

## Web Dashboard Features

- Real-time alert feed with live flash on new events
- Threat level badge: NONE / LOW / ELEVATED / HIGH / CRITICAL
- IP Investigation panel — click any row to profile the attacker
- Top Attackers ranking with visual bars
- Rule breakdown sidebar
- Severity distribution donut chart
- Alert timeline per minute
- Attack type breakdown bar chart
- Double-click any row for full alert detail modal

---

## Real Attack Testing (from Kali Linux)

    # Port scan
    sudo nmap -sS <target-ip> --min-rate 1000

    # SYN flood
    sudo hping3 -S --flood -p 80 <target-ip>

    # ICMP flood
    sudo hping3 --icmp --flood <target-ip>

    # XMAS scan
    sudo nmap -sX <target-ip>

    # NULL scan
    sudo nmap -sN <target-ip>

---

## Legal Notice

This tool is developed strictly for educational purposes as part of the CodeAlpha Cybersecurity Internship.
Only use it on networks you own or have explicit permission to monitor.

---

*CodeAlpha Cybersecurity Internship — Task 4: Network Intrusion Detection System*
*LBIEN Bilal | ENSA Fes | github.com/b1l4l-sec*
