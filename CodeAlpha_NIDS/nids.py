#!/usr/bin/env python3
"""
=============================================================================
 CodeAlpha Internship -- Task 4: Network Intrusion Detection System
 Author  : Lbien Bilal
 GitHub  : github.com/b1l4l-sec
 Program : Cycle Ingenieur GDNC -- ENSA Fes
 Contact : lbienbilal@gmail.com
=============================================================================

Usage:
  python3 nids.py                     Terminal log mode (simulated traffic)
  python3 nids.py --demo --dashboard  Full-screen terminal dashboard
  python3 nids.py --demo --web        Web dashboard at http://localhost:5000
  python3 nids.py --live              Live capture (requires root + scapy)
  python3 nids.py --live --iface eth0 --web
"""

import argparse
import threading
import os
import time

from detector import DetectionEngine
from sniffer  import SimulatedSniffer, SCAPY_AVAILABLE

try:
    from display import (
        rich_alert_handler, simple_alert_handler,
        print_banner, Dashboard, RICH_AVAILABLE
    )
except ImportError:
    RICH_AVAILABLE = False
    def rich_alert_handler(a):    print(a)
    def simple_alert_handler(a):  print(a)
    def print_banner():            print("=== CodeAlpha NIDS | Lbien Bilal ===")


def parse_args():
    p = argparse.ArgumentParser(
        prog="nids.py",
        description=(
            "CodeAlpha NIDS -- Rule-based Network Intrusion Detection System\n"
            "Author: Lbien Bilal | github.com/b1l4l-sec"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--live",       action="store_true",
                   help="Capture live traffic (requires root privileges and scapy)")
    p.add_argument("--demo",       action="store_true",
                   help="Use simulated attack traffic -- no root required (default)")
    p.add_argument("--iface",      default=None,
                   help="Network interface for live capture (e.g. eth0, wlan0)")
    p.add_argument("--web",        action="store_true",
                   help="Launch web dashboard at http://localhost:5000")
    p.add_argument("--web-port",   type=int, default=5000,
                   help="Web dashboard port (default: 5000)")
    p.add_argument("--dashboard",  action="store_true",
                   help="Full-screen Rich terminal dashboard")
    p.add_argument("--log",        default="logs/alerts.json",
                   help="Alert log output path (default: logs/alerts.json)")
    p.add_argument("--speed",      type=float, default=0.05,
                   help="Simulation interval in seconds (default: 0.05)")
    return p.parse_args()


def main():
    args = parse_args()
    os.makedirs("logs", exist_ok=True)

    alert_handler = rich_alert_handler if RICH_AVAILABLE else simple_alert_handler

    engine = DetectionEngine(
        alert_callback=alert_handler if not args.dashboard else lambda _: None,
        log_file=args.log,
    )

    # --- Sniffer selection ---------------------------------------------------
    if args.live and SCAPY_AVAILABLE:
        from sniffer import LiveSniffer
        print(f"[INFO] Starting live capture -- interface: {args.iface or 'system default'}")
        print("[INFO] Root privileges may be required for raw socket access.")
        sniffer = LiveSniffer(engine, iface=args.iface)
    else:
        if args.live and not SCAPY_AVAILABLE:
            print("[WARN] Scapy is not available. Falling back to simulation mode.")
        sniffer = SimulatedSniffer(engine, speed=args.speed)

    # --- Web dashboard -------------------------------------------------------
    if args.web:
        try:
            from dashboard_web import run_web, set_engine
            set_engine(engine)
            threading.Thread(
                target=run_web,
                kwargs={"port": args.web_port},
                daemon=True,
            ).start()
            print(f"[INFO] Web dashboard available at http://localhost:{args.web_port}")
        except ImportError:
            print("[WARN] Flask not installed. Web dashboard unavailable.")

    # --- Start capture -------------------------------------------------------
    sniffer.start()

    if args.dashboard and RICH_AVAILABLE:
        Dashboard(engine, sniffer, refresh_rate=1.0).run()
    else:
        if not args.web:
            print_banner()
        print("[INFO] Monitoring network traffic. Press Ctrl+C to stop.\n")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

    # --- Shutdown ------------------------------------------------------------
    sniffer.stop()
    stats = engine.get_stats()
    print(f"\n[INFO] NIDS stopped.")
    print(f"       Packets processed  : {sniffer.captured:,}")
    print(f"       Total alerts fired : {stats.get('total', 0)}")
    print(f"       Log file           : {args.log}")


if __name__ == "__main__":
    main()