"""
packet_analyzer.py — Deep packet inspection for common protocols.
Supports: Ethernet, ARP, IP, IPv6, TCP, UDP, ICMP, DNS, HTTP, HTTPS/TLS
"""

from scapy.all import (
    Ether, ARP, IP, IPv6,
    TCP, UDP, ICMP, ICMPv6Unknown,
    DNS, Raw,
)


# ── Protocol port mapping ──────────────────────────────────────────────────────
PORT_MAP = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
    25: "SMTP",     53: "DNS", 67: "DHCP", 68: "DHCP",
    69: "TFTP",     80: "HTTP", 110: "POP3", 123: "NTP",
    143: "IMAP",   161: "SNMP", 179: "BGP", 443: "HTTPS",
    445: "SMB",    500: "ISAKMP", 514: "SYSLOG", 587: "SMTP-TLS",
    636: "LDAPS",  993: "IMAPS", 995: "POP3S", 1194: "OpenVPN",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}

TCP_FLAGS = {
    0x01: "FIN", 0x02: "SYN", 0x04: "RST",
    0x08: "PSH", 0x10: "ACK", 0x20: "URG",
    0x40: "ECE", 0x80: "CWR",
}


def resolve_port(port: int) -> str:
    return PORT_MAP.get(port, str(port))


def decode_flags(flags_int: int) -> str:
    active = [name for bit, name in TCP_FLAGS.items() if flags_int & bit]
    return "+".join(active) if active else "NONE"


def extract_payload(packet, max_bytes: int = 64) -> str:
    """Return a safe printable snippet of the raw payload."""
    if Raw in packet:
        raw = bytes(packet[Raw].load)
        try:
            text = raw[:max_bytes].decode("utf-8", errors="replace")
            # keep only printable ASCII
            text = "".join(c if 32 <= ord(c) < 127 else "." for c in text)
            return text if text.strip() else None
        except Exception:
            return raw[:max_bytes].hex()
    return None


def analyze_dns(packet) -> dict:
    """Parse DNS query / response."""
    dns_info = {}
    if DNS in packet:
        dns = packet[DNS]
        dns_info["dns_id"] = dns.id
        dns_info["dns_type"] = "RESPONSE" if dns.qr else "QUERY"
        if dns.qd:
            try:
                dns_info["dns_name"] = dns.qd.qname.decode("utf-8").rstrip(".")
            except Exception:
                dns_info["dns_name"] = str(dns.qd.qname)
        if dns.qr and dns.an:
            answers = []
            ans = dns.an
            while ans:
                try:
                    if hasattr(ans, "rdata"):
                        answers.append(str(ans.rdata))
                except Exception:
                    pass
                ans = ans.payload if hasattr(ans, "payload") else None
                if not hasattr(ans, "rdata"):
                    break
            dns_info["dns_answers"] = answers[:3]  # cap at 3
    return dns_info


def analyze_http(packet) -> dict:
    """Try to extract HTTP method / host / path from raw payload."""
    http_info = {}
    if Raw in packet:
        try:
            raw = packet[Raw].load.decode("utf-8", errors="replace")
            lines = raw.split("\r\n")
            first = lines[0]
            # Request line: METHOD path HTTP/x.x
            methods = ("GET", "POST", "PUT", "DELETE", "PATCH",
                       "HEAD", "OPTIONS", "CONNECT", "TRACE")
            for m in methods:
                if first.startswith(m + " "):
                    parts = first.split(" ")
                    http_info["http_method"] = parts[0]
                    http_info["http_path"]   = parts[1] if len(parts) > 1 else "/"
                    for line in lines[1:]:
                        if line.lower().startswith("host:"):
                            http_info["http_host"] = line.split(":", 1)[1].strip()
                    break
            # Response line: HTTP/x.x 200 OK
            if first.startswith("HTTP/"):
                parts = first.split(" ", 2)
                http_info["http_status"] = parts[1] if len(parts) > 1 else "?"
                http_info["http_reason"] = parts[2] if len(parts) > 2 else ""
        except Exception:
            pass
    return http_info


def analyze_tls(packet) -> dict:
    """Detect TLS handshake type from raw bytes."""
    tls_info = {}
    if Raw in packet:
        raw = bytes(packet[Raw].load)
        if len(raw) >= 6 and raw[0] == 0x16:  # TLS Handshake
            content_type = {0x14: "ChangeCipherSpec", 0x15: "Alert",
                            0x16: "Handshake",        0x17: "AppData"}
            handshake_type = {0x01: "ClientHello",  0x02: "ServerHello",
                              0x0B: "Certificate",   0x0C: "ServerKeyExchange",
                              0x0E: "ServerHelloDone", 0x10: "ClientKeyExchange",
                              0x14: "Finished"}
            tls_info["tls_record"] = content_type.get(raw[0], "Unknown")
            tls_info["tls_version"] = f"{raw[1]}.{raw[2]}"
            if raw[0] == 0x16 and len(raw) > 5:
                tls_info["tls_handshake"] = handshake_type.get(raw[5], "Unknown")
    return tls_info


# ── Main analyzer ──────────────────────────────────────────────────────────────

def analyze_packet(packet) -> dict:
    """
    Dissect a scapy packet and return a structured info dict.
    """
    info = {
        "protocol":   "UNKNOWN",
        "src_ip":     "?",
        "dst_ip":     "?",
        "src_port":   None,
        "dst_port":   None,
        "src_mac":    None,
        "dst_mac":    None,
        "size":       len(packet),
        "flags":      None,
        "service":    None,
        "payload":    None,
        "extra":      {},
    }

    # ── Layer 2: Ethernet ──────────────────────────────────────────────────────
    if Ether in packet:
        info["src_mac"] = packet[Ether].src
        info["dst_mac"] = packet[Ether].dst

    # ── Layer 3: ARP ───────────────────────────────────────────────────────────
    if ARP in packet:
        arp = packet[ARP]
        info["protocol"] = "ARP"
        info["src_ip"]   = arp.psrc
        info["dst_ip"]   = arp.pdst
        op = "REQUEST" if arp.op == 1 else "REPLY"
        info["extra"]["arp_op"] = op
        info["extra"]["arp_hwsrc"] = arp.hwsrc
        return info

    # ── Layer 3: IP ────────────────────────────────────────────────────────────
    if IP in packet:
        ip = packet[IP]
        info["src_ip"] = ip.src
        info["dst_ip"] = ip.dst
        info["extra"]["ttl"] = ip.ttl

    elif IPv6 in packet:
        ip6 = packet[IPv6]
        info["src_ip"] = ip6.src
        info["dst_ip"] = ip6.dst
        info["extra"]["hop_limit"] = ip6.hlim

    # ── Layer 3: ICMP ──────────────────────────────────────────────────────────
    if ICMP in packet:
        icmp = packet[ICMP]
        info["protocol"] = "ICMP"
        icmp_types = {0: "Echo Reply", 3: "Dest Unreachable",
                      8: "Echo Request", 11: "Time Exceeded"}
        info["extra"]["icmp_type"] = icmp_types.get(icmp.type, str(icmp.type))
        return info

    # ── Layer 4: TCP ───────────────────────────────────────────────────────────
    if TCP in packet:
        tcp = packet[TCP]
        info["src_port"] = tcp.sport
        info["dst_port"] = tcp.dport
        info["flags"]    = decode_flags(int(tcp.flags))
        info["extra"]["seq"] = tcp.seq
        info["extra"]["ack"] = tcp.ack

        sport_svc = PORT_MAP.get(tcp.sport)
        dport_svc = PORT_MAP.get(tcp.dport)
        svc = dport_svc or sport_svc

        # Identify application layer
        if tcp.dport == 80 or tcp.sport == 80:
            info["protocol"] = "HTTP"
            info["service"]  = "HTTP"
            info["extra"].update(analyze_http(packet))
        elif tcp.dport == 443 or tcp.sport == 443:
            info["protocol"] = "HTTPS/TLS"
            info["service"]  = "HTTPS"
            info["extra"].update(analyze_tls(packet))
        elif svc:
            info["protocol"] = svc
            info["service"]  = svc
        else:
            info["protocol"] = "TCP"

        info["payload"] = extract_payload(packet)
        return info

    # ── Layer 4: UDP ───────────────────────────────────────────────────────────
    if UDP in packet:
        udp = packet[UDP]
        info["src_port"] = udp.sport
        info["dst_port"] = udp.dport

        if DNS in packet:
            info["protocol"] = "DNS"
            info["service"]  = "DNS"
            info["extra"].update(analyze_dns(packet))
        else:
            sport_svc = PORT_MAP.get(udp.sport)
            dport_svc = PORT_MAP.get(udp.dport)
            svc = dport_svc or sport_svc
            info["protocol"] = svc if svc else "UDP"
            info["service"]  = svc

        info["payload"] = extract_payload(packet)
        return info

    # Fallback
    info["protocol"] = packet.__class__.__name__
    return info
