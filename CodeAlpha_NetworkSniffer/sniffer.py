#!/usr/bin/env python3
"""
CodeAlpha Internship — Task 1: Basic Network Sniffer
Author  : LBIEN Bilal
GitHub  : github.com/b1l4l-sec
"""

import argparse
import sys
from scapy.all import sniff, get_if_list
from packet_analyzer import analyze_packet
from display import print_banner, print_packet, print_summary
from collections import defaultdict
import signal

# ── Global stats ──────────────────────────────────────────────────────────────
stats = defaultdict(int)
packet_count = 0


def packet_callback(packet):
    """Called for every captured packet."""
    global packet_count
    packet_count += 1
    info = analyze_packet(packet)
    stats[info["protocol"]] += 1
    print_packet(packet_count, info)


def graceful_exit(sig, frame):
    """Handle Ctrl+C — show summary then exit."""
    print("\n")
    print_summary(packet_count, stats)
    sys.exit(0)


def list_interfaces():
    """Print available network interfaces."""
    print("\n[*] Available interfaces:")
    for iface in get_if_list():
        print(f"    - {iface}")
    print()


def main():
    signal.signal(signal.SIGINT, graceful_exit)

    parser = argparse.ArgumentParser(
        description="CodeAlpha Network Sniffer — Bilal LBIEN",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-i", "--interface",
        default=None,
        help="Network interface to sniff on (e.g. eth0, ens33)\nLeave empty to use default.",
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Number of packets to capture (0 = unlimited)",
    )
    parser.add_argument(
        "-f", "--filter",
        default=None,
        help='BPF filter string (e.g. "tcp", "udp port 53", "icmp")',
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit",
    )

    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
        sys.exit(0)

    print_banner()

    # Build sniff kwargs
    kwargs = {
        "prn": packet_callback,
        "store": False,          # don't keep packets in memory
        "count": args.count,
    }
    if args.interface:
        kwargs["iface"] = args.interface
    if args.filter:
        kwargs["filter"] = args.filter

    iface_label = args.interface or "default"
    filter_label = args.filter or "none"
    count_label  = str(args.count) if args.count else "unlimited"

    print(f"  Interface : {iface_label}")
    print(f"  Filter    : {filter_label}")
    print(f"  Count     : {count_label}")
    print(f"  Press Ctrl+C to stop and show summary\n")
    print("─" * 72)

    try:
        sniff(**kwargs)
    except PermissionError:
        print("\n[!] Permission denied — run with sudo:\n    sudo python3 sniffer.py\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}\n")
        sys.exit(1)

    # Reached if --count was set
    print_summary(packet_count, stats)


if __name__ == "__main__":
    main()
