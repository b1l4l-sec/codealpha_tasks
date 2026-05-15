"""
display.py — Rich terminal output with colors for the network sniffer.
"""

from colorama import init, Fore, Back, Style
from datetime import datetime

init(autoreset=True)

# ── Color scheme ───────────────────────────────────────────────────────────────
PROTO_COLORS = {
    "HTTP":      Fore.GREEN,
    "HTTPS/TLS": Fore.CYAN,
    "DNS":       Fore.YELLOW,
    "TCP":       Fore.BLUE,
    "UDP":       Fore.MAGENTA,
    "ICMP":      Fore.WHITE,
    "ARP":       Fore.LIGHTRED_EX,
    "SSH":       Fore.LIGHTCYAN_EX,
    "FTP":       Fore.LIGHTYELLOW_EX,
    "SMTP":      Fore.LIGHTMAGENTA_EX,
    "RDP":       Fore.LIGHTRED_EX,
    "SMB":       Fore.LIGHTRED_EX,
    "NTP":       Fore.LIGHTWHITE_EX,
}

SEVERITY = {
    "TELNET":   ("[CLEARTEXT]", Fore.RED),
    "FTP":      ("[CLEARTEXT]", Fore.RED),
    "SMB":      ("[LATERAL]",   Fore.LIGHTYELLOW_EX),
    "RDP":      ("[REMOTE]",    Fore.LIGHTYELLOW_EX),
    "ARP":      ("[L2]",        Fore.LIGHTWHITE_EX),
}


def proto_color(protocol: str) -> str:
    for key, color in PROTO_COLORS.items():
        if protocol.startswith(key):
            return color
    return Fore.WHITE


def print_banner():
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════╗
║  {Fore.WHITE}{Style.BRIGHT}CodeAlpha Network Sniffer — Task 1                  {Fore.CYAN}             ║
║  {Fore.LIGHTBLACK_EX}Author : LBIEN Bilal  |  github.com/b1l4l-sec{Fore.CYAN}                       ║
║  {Fore.LIGHTBLACK_EX}Built  : Python + Scapy  |  Multi-protocol analyzer{Fore.CYAN}                 ║
╚══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)


def format_port(port) -> str:
    if port is None:
        return ""
    return f":{port}"


def print_packet(index: int, info: dict):
    """Print a single packet in a structured colored line."""
    ts      = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    proto   = info["protocol"]
    color   = proto_color(proto)
    size    = info["size"]
    src_ip  = info["src_ip"]
    dst_ip  = info["dst_ip"]
    src_p   = format_port(info["src_port"])
    dst_p   = format_port(info["dst_port"])
    flags   = info["flags"] or ""
    extra   = info["extra"]

    # ── Severity tag ──────────────────────────────────────────────────────────
    sev_tag = ""
    if proto in SEVERITY:
        tag, tag_color = SEVERITY[proto]
        sev_tag = f" {tag_color}[{tag}]{Style.RESET_ALL}"

    # ── Main line ─────────────────────────────────────────────────────────────
    proto_label = f"{color}{Style.BRIGHT}{proto:<12}{Style.RESET_ALL}"
    arrow       = f"{Fore.LIGHTBLACK_EX}→{Style.RESET_ALL}"
    src_label   = f"{Fore.LIGHTWHITE_EX}{src_ip}{src_p}{Style.RESET_ALL}"
    dst_label   = f"{Fore.LIGHTWHITE_EX}{dst_ip}{dst_p}{Style.RESET_ALL}"
    size_label  = f"{Fore.LIGHTBLACK_EX}{size}B{Style.RESET_ALL}"
    idx_label   = f"{Fore.LIGHTBLACK_EX}#{index:<5}{Style.RESET_ALL}"
    ts_label    = f"{Fore.LIGHTBLACK_EX}{ts}{Style.RESET_ALL}"
    flags_label = f" {Fore.LIGHTBLACK_EX}[{flags}]{Style.RESET_ALL}" if flags else ""

    print(f"{idx_label} {ts_label}  {proto_label}  {src_label} {arrow} {dst_label}  {size_label}{flags_label}{sev_tag}")

    # ── Extra details (indented) ───────────────────────────────────────────────
    details = []

    # DNS
    if "dns_name" in extra:
        dtype = extra.get("dns_type", "")
        name  = extra.get("dns_name", "")
        answers = extra.get("dns_answers", [])
        ans_str = " → " + ", ".join(answers) if answers else ""
        details.append(f"DNS {dtype}: {name}{ans_str}")

    # HTTP request
    if "http_method" in extra:
        host = extra.get("http_host", "")
        path = extra.get("http_path", "/")
        details.append(f"HTTP {extra['http_method']} {host}{path}")

    # HTTP response
    if "http_status" in extra:
        details.append(f"HTTP {extra['http_status']} {extra.get('http_reason','')}")

    # TLS handshake
    if "tls_handshake" in extra:
        details.append(f"TLS Handshake: {extra['tls_handshake']}")

    # ARP
    if "arp_op" in extra:
        op = extra.get("arp_op", "")
        hw = extra.get("arp_hwsrc", "")
        details.append(f"ARP {op}  hw={hw}")

    # ICMP
    if "icmp_type" in extra:
        details.append(f"ICMP {extra['icmp_type']}")

    # MAC addresses
    if info.get("src_mac") and proto not in ("HTTP", "HTTPS/TLS", "DNS", "TCP", "UDP"):
        details.append(f"MAC {info['src_mac']} → {info['dst_mac']}")

    for d in details:
        print(f"         {Fore.LIGHTBLACK_EX}↳ {Fore.LIGHTYELLOW_EX}{d}{Style.RESET_ALL}")

    # Payload snippet (only for cleartext protocols)
    if info.get("payload") and proto in ("HTTP", "FTP", "TELNET", "SMTP"):
        snippet = info["payload"][:80]
        print(f"         {Fore.LIGHTBLACK_EX}↳ payload: {Fore.RED}{snippet}{Style.RESET_ALL}")


def print_summary(total: int, stats: dict):
    """Print a summary table after capture stops."""
    print(f"\n{Fore.CYAN}{'─'*72}")
    print(f"{Style.BRIGHT}  Capture Summary{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'─'*72}{Style.RESET_ALL}")
    print(f"  Total packets captured : {Style.BRIGHT}{Fore.WHITE}{total}{Style.RESET_ALL}")
    print()
    if stats:
        sorted_stats = sorted(stats.items(), key=lambda x: x[1], reverse=True)
        for proto, count in sorted_stats:
            bar_len = int((count / total) * 30) if total else 0
            bar     = "█" * bar_len + "░" * (30 - bar_len)
            color   = proto_color(proto)
            pct     = (count / total * 100) if total else 0
            print(f"  {color}{proto:<14}{Style.RESET_ALL} {Fore.LIGHTBLACK_EX}{bar}{Style.RESET_ALL}  {count:>5} ({pct:.1f}%)")
    print(f"\n{Fore.CYAN}{'─'*72}{Style.RESET_ALL}\n")
