"""
=============================================================================
 CodeAlpha Internship -- Task 4: Network Intrusion Detection System
 Module  : detector.py -- Rule-based detection engine
 Author  : Lbien Bilal
 GitHub  : github.com/b1l4l-sec
 Program : Cycle Ingenieur GDNC -- ENSA Fes
 Contact : lbienbilal@gmail.com
=============================================================================

Detects: SYN Flood, ICMP Flood, Port Scan, Brute Force, ARP Spoofing,
         NULL/FIN/XMAS Scans, Suspicious Payloads, DNS Amplification.
All detections use a sliding time-window algorithm with per-IP state tracking.
"""

import time
import json
import threading
from collections import defaultdict, deque
from datetime import datetime


SEVERITY = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class Alert:
    """Represents a single intrusion detection event."""

    def __init__(self, rule_name, severity, src_ip, dst_ip, proto, detail, pkt_summary=""):
        self.timestamp   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.rule_name   = rule_name
        self.severity    = severity
        self.src_ip      = src_ip
        self.dst_ip      = dst_ip
        self.proto       = proto
        self.detail      = detail
        self.pkt_summary = pkt_summary

    def to_dict(self):
        return {
            "timestamp":   self.timestamp,
            "rule":        self.rule_name,
            "severity":    self.severity,
            "src_ip":      self.src_ip,
            "dst_ip":      self.dst_ip,
            "proto":       self.proto,
            "detail":      self.detail,
            "pkt_summary": self.pkt_summary,
        }

    def __str__(self):
        return (
            f"[{self.timestamp}] [{self.severity:8s}] {self.rule_name:25s} "
            f"{self.src_ip:>15s} -> {self.dst_ip:<15s} | {self.detail}"
        )


class DetectionEngine:
    """
    Core detection engine.
    Each rule operates on a sliding time window; counters reset after a
    detection fires to avoid redundant alerts for the same ongoing attack.
    """

    # --- Detection thresholds (tunable) -------------------------------------
    PORT_SCAN_THRESHOLD   = 5    # unique destination ports per window
    SYN_FLOOD_THRESHOLD   = 20   # SYN packets per window
    ICMP_FLOOD_THRESHOLD  = 5    # ICMP echo requests per window
    BRUTE_FORCE_THRESHOLD = 10    # connection attempts to a sensitive port
    DNS_AMP_THRESHOLD     = 20    # large DNS responses per window
    WINDOW_SECONDS        = 10    # sliding window duration (seconds)

    # --- Payload signatures --------------------------------------------------
    PAYLOAD_SIGNATURES = [
        (b"/etc/passwd",   "LFI attempt detected"),
        (b"SELECT ",       "SQL Injection pattern"),
        (b"UNION SELECT",  "SQL Injection (UNION-based)"),
        (b"<script>",      "Cross-Site Scripting (XSS)"),
        (b"cmd.exe",       "Command injection (Windows)"),
        (b"/bin/sh",       "Command injection (Unix)"),
        (b"../../",        "Directory traversal"),
        (b"eval(",         "Code evaluation injection"),
        (b"base64_decode", "Encoded payload (base64)"),
        (b"powershell",    "PowerShell execution attempt"),
    ]

    # --- Sensitive service ports ---------------------------------------------
    SENSITIVE_PORTS = {
        22:   "SSH",
        23:   "Telnet",
        3389: "RDP",
        21:   "FTP",
        5900: "VNC",
        3306: "MySQL",
        5432: "PostgreSQL",
        1433: "MSSQL",
    }

    def __init__(self, alert_callback=None, log_file="logs/alerts.json"):
        self.alert_callback = alert_callback or (lambda a: None)
        self.log_file       = log_file
        self.lock           = threading.Lock()
        self.alerts         = []

        # Per-IP state (deques of event timestamps)
        self._syn_tracker     = defaultdict(deque)
        self._icmp_tracker    = defaultdict(deque)
        self._port_tracker    = defaultdict(lambda: defaultdict(deque))
        self._brute_tracker   = defaultdict(lambda: defaultdict(deque))
        self._dns_amp_tracker = defaultdict(deque)
        self._arp_table       = {}   # ip -> mac (ARP spoofing baseline)

        self.stats = defaultdict(int)

    # --- Internal helpers ----------------------------------------------------

    def _now(self):
        return time.time()

    def _prune(self, dq, window=None):
        """Remove events older than the sliding window from a deque."""
        cutoff = self._now() - (window or self.WINDOW_SECONDS)
        while dq and dq[0] < cutoff:
            dq.popleft()

    def _fire(self, alert: Alert):
        """Record, log, and dispatch a fired alert."""
        with self.lock:
            self.alerts.append(alert)
            self.stats[alert.severity] += 1
            self.stats["total"] += 1
        self.alert_callback(alert)
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(alert.to_dict()) + "\n")
        except OSError:
            pass

    # --- Detection rules -----------------------------------------------------

    def check_syn_flood(self, src_ip, dst_ip, pkt_summary=""):
        dq = self._syn_tracker[src_ip]
        dq.append(self._now())
        self._prune(dq)
        if len(dq) >= self.SYN_FLOOD_THRESHOLD:
            self._fire(Alert(
                "SYN Flood", "HIGH", src_ip, dst_ip, "TCP",
                f"{len(dq)} SYN packets in {self.WINDOW_SECONDS}s", pkt_summary,
            ))
            dq.clear()

    def check_icmp_flood(self, src_ip, dst_ip, pkt_summary=""):
        dq = self._icmp_tracker[src_ip]
        dq.append(self._now())
        self._prune(dq)
        if len(dq) >= self.ICMP_FLOOD_THRESHOLD:
            self._fire(Alert(
                "ICMP Flood", "MEDIUM", src_ip, dst_ip, "ICMP",
                f"{len(dq)} ICMP echo requests in {self.WINDOW_SECONDS}s", pkt_summary,
            ))
            dq.clear()

    def check_port_scan(self, src_ip, dst_ip, dst_port, pkt_summary=""):
        dq = self._port_tracker[src_ip][dst_port]
        dq.append(self._now())
        self._prune(dq)
        # Evict stale port entries
        stale = [
            p for p, q in self._port_tracker[src_ip].items()
            if not q or (self._now() - q[-1]) > self.WINDOW_SECONDS
        ]
        for p in stale:
            del self._port_tracker[src_ip][p]
        if len(self._port_tracker[src_ip]) >= self.PORT_SCAN_THRESHOLD:
            self._fire(Alert(
                "Port Scan", "HIGH", src_ip, dst_ip, "TCP/UDP",
                f"{len(self._port_tracker[src_ip])} distinct ports probed "
                f"in {self.WINDOW_SECONDS}s", pkt_summary,
            ))
            self._port_tracker[src_ip].clear()

    def check_brute_force(self, src_ip, dst_ip, dst_port, pkt_summary=""):
        if dst_port not in self.SENSITIVE_PORTS:
            return
        dq = self._brute_tracker[src_ip][dst_port]
        dq.append(self._now())
        self._prune(dq)
        if len(dq) >= self.BRUTE_FORCE_THRESHOLD:
            svc = self.SENSITIVE_PORTS[dst_port]
            self._fire(Alert(
                "Brute Force", "CRITICAL", src_ip, dst_ip, svc,
                f"{len(dq)} connection attempts to {svc} (port {dst_port}) "
                f"in {self.WINDOW_SECONDS}s", pkt_summary,
            ))
            dq.clear()

    def check_payload(self, src_ip, dst_ip, proto, payload: bytes, pkt_summary=""):
        if not payload:
            return
        payload_lower = payload.lower()
        for sig, desc in self.PAYLOAD_SIGNATURES:
            if sig.lower() in payload_lower:
                self._fire(Alert(
                    "Suspicious Payload", "HIGH", src_ip, dst_ip, proto,
                    desc, pkt_summary,
                ))

    def check_dns_amplification(self, src_ip, dst_ip, resp_size, pkt_summary=""):
        if resp_size < 512:
            return
        dq = self._dns_amp_tracker[src_ip]
        dq.append(self._now())
        self._prune(dq)
        if len(dq) >= self.DNS_AMP_THRESHOLD:
            self._fire(Alert(
                "DNS Amplification", "HIGH", src_ip, dst_ip, "DNS",
                f"{len(dq)} oversized DNS responses ({resp_size} B) "
                f"in {self.WINDOW_SECONDS}s", pkt_summary,
            ))
            dq.clear()

    def check_arp_spoofing(self, src_ip, src_mac, pkt_summary=""):
        if src_ip in self._arp_table:
            known_mac = self._arp_table[src_ip]
            if known_mac != src_mac:
                self._fire(Alert(
                    "ARP Spoofing", "CRITICAL", src_ip, "broadcast", "ARP",
                    f"MAC address changed: {known_mac} -> {src_mac}", pkt_summary,
                ))
        self._arp_table[src_ip] = src_mac

    def check_null_scan(self, src_ip, dst_ip, flags, pkt_summary=""):
        """Detect NULL (0x00), FIN (0x01), and XMAS (0x29) TCP scans."""
        if flags == 0x00:
            self._fire(Alert(
                "NULL Scan", "MEDIUM", src_ip, dst_ip, "TCP",
                "TCP segment with no flags set (NULL scan)", pkt_summary,
            ))
        elif flags == 0x01:
            self._fire(Alert(
                "FIN Scan", "MEDIUM", src_ip, dst_ip, "TCP",
                "TCP FIN-only scan detected", pkt_summary,
            ))
        elif flags == 0x29:
            self._fire(Alert(
                "XMAS Scan", "MEDIUM", src_ip, dst_ip, "TCP",
                "TCP XMAS scan detected (FIN+PSH+URG)", pkt_summary,
            ))

    # --- Accessors -----------------------------------------------------------

    def get_stats(self):
        with self.lock:
            return dict(self.stats)

    def get_recent_alerts(self, n=50):
        with self.lock:
            return list(self.alerts[-n:])