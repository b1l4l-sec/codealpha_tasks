"""
=============================================================================
 CodeAlpha Internship -- Task 4: Network Intrusion Detection System
 Module  : sniffer.py -- Packet capture and traffic simulation
 Author  : Lbien Bilal
 GitHub  : github.com/b1l4l-sec
 Program : Cycle Ingenieur GDNC -- ENSA Fes
 Contact : lbienbilal@gmail.com
=============================================================================

LiveSniffer      -- Raw packet capture via Scapy (requires root).
SimulatedSniffer -- Deterministic attack scenario generator for demo/testing.
PacketProcessor  -- Parses captured packets and routes them to the engine.
"""

import threading
import time
import random

from detector import DetectionEngine

try:
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP, DNS, ARP, Raw,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# =============================================================================
# Packet Processor
# =============================================================================

class PacketProcessor:
    """
    Routes each captured packet to the appropriate detection checks
    based on its protocol stack.
    """

    def __init__(self, engine: DetectionEngine):
        self.engine       = engine
        self.packet_count = 0

    def process(self, pkt):
        self.packet_count += 1
        summary = pkt.summary() if SCAPY_AVAILABLE else str(pkt)

        # ARP
        if SCAPY_AVAILABLE and pkt.haslayer(ARP):
            arp = pkt[ARP]
            if arp.op == 2:  # reply
                self.engine.check_arp_spoofing(arp.psrc, arp.hwsrc, summary)
            return

        if SCAPY_AVAILABLE and not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        # ICMP
        if SCAPY_AVAILABLE and pkt.haslayer(ICMP):
            if pkt[ICMP].type == 8:
                self.engine.check_icmp_flood(src_ip, dst_ip, summary)
            return

        # DNS
        if SCAPY_AVAILABLE and pkt.haslayer(DNS):
            dns = pkt[DNS]
            if dns.qr == 1:  # response
                self.engine.check_dns_amplification(
                    src_ip, dst_ip, len(bytes(pkt)), summary
                )
            return

        # TCP
        if SCAPY_AVAILABLE and pkt.haslayer(TCP):
            tcp     = pkt[TCP]
            dport   = tcp.dport
            flags   = int(tcp.flags)
            syn_set = bool(flags & 0x02)
            ack_set = bool(flags & 0x10)

            if syn_set and not ack_set:
                self.engine.check_syn_flood(src_ip, dst_ip, summary)
                self.engine.check_brute_force(src_ip, dst_ip, dport, summary)

            self.engine.check_port_scan(src_ip, dst_ip, dport, summary)

            if not syn_set and not ack_set:
                self.engine.check_null_scan(src_ip, dst_ip, flags, summary)

            if pkt.haslayer(Raw):
                self.engine.check_payload(
                    src_ip, dst_ip, "TCP", bytes(pkt[Raw].load), summary
                )
            return

        # UDP
        if SCAPY_AVAILABLE and pkt.haslayer(UDP):
            if pkt.haslayer(Raw):
                self.engine.check_payload(
                    src_ip, dst_ip, "UDP", bytes(pkt[Raw].load), summary
                )


# =============================================================================
# Live Sniffer (Scapy)
# =============================================================================

class LiveSniffer:
    """Captures packets from a network interface using Scapy."""

    def __init__(self, engine: DetectionEngine, iface=None):
        self.engine     = engine
        self.iface      = iface
        self.processor  = PacketProcessor(engine)
        self._stop_evt  = threading.Event()
        self._thread    = None

    def _run(self):
        try:
            sniff(
                iface=self.iface,
                prn=self.processor.process,
                store=False,
                stop_filter=lambda _: self._stop_evt.is_set(),
            )
        except Exception as exc:
            print(f"[ERROR] Sniffer: {exc}")

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_evt.set()

    @property
    def captured(self):
        return self.processor.packet_count


# =============================================================================
# Simulated Sniffer (Demo / Testing)
# =============================================================================

def _rand_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def _rand_mac():
    return ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))


class SimulatedSniffer:
    """
    Generates synthetic network traffic covering all 10 attack scenarios.
    Designed for demonstration and testing without root access.
    """

    VICTIM_IP    = "10.0.0.5"
    MAC_LEGIT    = "aa:bb:cc:dd:ee:ff"
    MAC_SPOOF    = "11:22:33:44:55:66"
    DNS_SERVER   = "8.8.8.8"

    def __init__(self, engine: DetectionEngine, speed: float = 0.05):
        self.engine       = engine
        self.speed        = speed
        self._stop_evt    = threading.Event()
        self._thread      = None
        self.packet_count = 0

    def _emit(self, fn, *args, **kwargs):
        """Call a detection method and increment the packet counter."""
        fn(*args, **kwargs)
        self.packet_count += 1

    def _simulate(self):
        victim    = self.VICTIM_IP
        cycle     = 0

        while not self._stop_evt.is_set():
            scenario = cycle % 10
            cycle   += 1
            src      = _rand_ip()

            if scenario == 0:
                # Port Scan
                for port in random.sample(range(1, 9000), 20):
                    if self._stop_evt.is_set(): break
                    self._emit(
                        self.engine.check_port_scan, src, victim, port,
                        f"TCP {src}:{random.randint(40000,65535)} > {victim}:{port} S",
                    )
                    time.sleep(self.speed * 0.2)

            elif scenario == 1:
                # SYN Flood
                for _ in range(110):
                    if self._stop_evt.is_set(): break
                    self._emit(
                        self.engine.check_syn_flood, src, victim,
                        f"TCP {src} > {victim}:80 S",
                    )
                    time.sleep(self.speed * 0.1)

            elif scenario == 2:
                # ICMP Flood
                for _ in range(55):
                    if self._stop_evt.is_set(): break
                    self._emit(
                        self.engine.check_icmp_flood, src, victim,
                        f"ICMP {src} > {victim} echo-request",
                    )
                    time.sleep(self.speed * 0.1)

            elif scenario == 3:
                # SSH Brute Force
                for _ in range(12):
                    if self._stop_evt.is_set(): break
                    self._emit(
                        self.engine.check_brute_force, src, victim, 22,
                        f"TCP {src} > {victim}:22 S",
                    )
                    time.sleep(self.speed * 0.3)

            elif scenario == 4:
                # ARP Spoofing
                target = f"10.0.0.{random.randint(2, 20)}"
                self._emit(
                    self.engine.check_arp_spoofing, target, self.MAC_LEGIT,
                    f"ARP {target} is-at {self.MAC_LEGIT}",
                )
                time.sleep(self.speed)
                self._emit(
                    self.engine.check_arp_spoofing, target, self.MAC_SPOOF,
                    f"ARP {target} is-at {self.MAC_SPOOF}",
                )

            elif scenario == 5:
                # LFI Payload
                self._emit(
                    self.engine.check_payload, src, victim, "TCP",
                    b"GET /index.php?page=../../etc/passwd HTTP/1.1",
                    f"TCP {src} > {victim}:80 [LFI]",
                )

            elif scenario == 6:
                # SQL Injection
                self._emit(
                    self.engine.check_payload, src, victim, "TCP",
                    b"POST /login HTTP/1.1\r\nusername=admin' UNION SELECT * FROM users--",
                    f"TCP {src} > {victim}:80 [SQLi]",
                )

            elif scenario == 7:
                # DNS Amplification
                for _ in range(25):
                    if self._stop_evt.is_set(): break
                    self._emit(
                        self.engine.check_dns_amplification, self.DNS_SERVER,
                        victim, 800,
                        f"DNS {self.DNS_SERVER} > {victim} resp=800B",
                    )
                    time.sleep(self.speed * 0.2)

            elif scenario == 8:
                # XMAS Scan
                self._emit(
                    self.engine.check_null_scan, src, victim, 0x29,
                    f"TCP {src} > {victim}:443 FPU",
                )

            else:
                # Benign traffic (no detection triggered)
                self.packet_count += 5
                time.sleep(self.speed * 5)

            time.sleep(self.speed)

    def start(self):
        self._thread = threading.Thread(target=self._simulate, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_evt.set()

    @property
    def captured(self):
        return self.packet_count