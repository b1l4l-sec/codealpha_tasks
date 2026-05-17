"""
=============================================================================
 CodeAlpha Internship -- Task 4: Network Intrusion Detection System
 Module  : display.py -- Terminal UI (Rich)
 Author  : Lbien Bilal
 GitHub  : github.com/b1l4l-sec
 Program : Cycle Ingenieur GDNC -- ENSA Fes
 Contact : lbienbilal@gmail.com
=============================================================================
"""

import time
from collections import defaultdict

try:
    from rich.console import Console
    from rich.table   import Table
    from rich.panel   import Panel
    from rich.layout  import Layout
    from rich.live    import Live
    from rich.text    import Text
    from rich         import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from detector import DetectionEngine

console = Console()

SEVERITY_COLORS = {
    "LOW":      "bright_blue",
    "MEDIUM":   "yellow",
    "HIGH":     "red",
    "CRITICAL": "bold red",
}

BANNER = (
    "  ____          _        _    _       _           _   _ ___ ____  ____\n"
    " / ___|___   __| | ___  / \\  | |_ __ | |__   __ _| \\ | |_ _|  _ \\/___| \n"
    "| |   / _ \\ / _`|/ _ \\/ _ \\ | | '_ \\| '_ \\ / _` |  \\| || || | | \\___  \\\n"
    "| |__| (_) | (_| |  __/ ___ \\| | |_) | | | | (_| | |\\  || || |_| |___) |\n"
    " \\____\\___/ \\__,_|\\___/_/   \\_\\_| .__/|_| |_|\\__,_|_| \\_|___|____/|____/\n"
    "                                  |_|\n"
    "\n"
    "  Network Intrusion Detection System  |  Lbien Bilal  |  github.com/b1l4l-sec\n"
    "  ENSA Fes -- Cycle Ingenieur GDNC   |  CodeAlpha Internship -- Task 4\n"
)


def print_banner():
    if RICH_AVAILABLE:
        console.print(Panel(BANNER, border_style="cyan", expand=False))
    else:
        print(BANNER)


def simple_alert_handler(alert):
    tag = {"LOW": "[LOW]", "MEDIUM": "[MED]",
           "HIGH": "[HIGH]", "CRITICAL": "[CRIT]"}.get(alert.severity, "[???]")
    print(
        f"{alert.timestamp} {tag:7s}  {alert.rule_name:25s} "
        f"{alert.src_ip:>15s} -> {alert.dst_ip:<15s}  {alert.detail}"
    )


def rich_alert_handler(alert):
    color = SEVERITY_COLORS.get(alert.severity, "white")
    console.print(
        f"[dim]{alert.timestamp}[/]  "
        f"[{color}][{alert.severity:8s}][/]  "
        f"[bold]{alert.rule_name:22s}[/]  "
        f"[cyan]{alert.src_ip:>15s}[/] [dim]->[/] [cyan]{alert.dst_ip:<15s}[/]  "
        f"{alert.detail}"
    )


class Dashboard:
    """Full-screen Rich terminal dashboard with live refresh."""

    def __init__(self, engine: DetectionEngine, sniffer, refresh_rate: float = 1.0):
        self.engine       = engine
        self.sniffer      = sniffer
        self.refresh_rate = refresh_rate
        self._start       = time.time()

    def _uptime(self):
        e = int(time.time() - self._start)
        h, r = divmod(e, 3600)
        m, s = divmod(r, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    def _header(self):
        stats  = self.engine.get_stats()
        return Panel(
            f"[bold cyan]CodeAlpha NIDS[/]  |  "
            f"[dim]Lbien Bilal -- github.com/b1l4l-sec[/]  |  "
            f"Uptime: [green]{self._uptime()}[/]  |  "
            f"Packets: [cyan]{self.sniffer.captured:,}[/]  |  "
            f"Alerts: [white]{stats.get('total', 0)}[/]  |  "
            f"CRITICAL: [bold red]{stats.get('CRITICAL', 0)}[/]  |  "
            f"HIGH: [red]{stats.get('HIGH', 0)}[/]",
            border_style="cyan",
        )

    def _alert_table(self):
        t = Table(
            title="[bold]Recent Alerts[/]",
            box=box.SIMPLE_HEAVY,
            header_style="bold magenta",
            expand=True,
        )
        t.add_column("Timestamp",    style="dim",       width=19)
        t.add_column("Severity",     justify="center",  width=10)
        t.add_column("Rule",                            width=22)
        t.add_column("Source IP",                       width=16)
        t.add_column("Destination",                     width=16)
        t.add_column("Detail",       no_wrap=False)
        for alert in reversed(self.engine.get_recent_alerts(25)):
            color = SEVERITY_COLORS.get(alert.severity, "white")
            t.add_row(
                alert.timestamp,
                Text(alert.severity, style=color),
                alert.rule_name,
                alert.src_ip,
                alert.dst_ip,
                alert.detail,
            )
        return t

    def _stats_panel(self):
        stats = self.engine.get_stats()
        lines = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            count = stats.get(sev, 0)
            color = SEVERITY_COLORS[sev]
            bar   = chr(0x2588) * min(count, 28)
            lines.append(f"[{color}]{sev:8s}[/] [{color}]{bar}[/] [white]{count}[/]")
        lines.append(f"\n[bold]Total:[/] [white]{stats.get('total', 0)}[/]")
        return Panel("\n".join(lines), title="[bold]Severity[/]", border_style="magenta")

    def _rule_table(self):
        alerts = self.engine.get_recent_alerts(200)
        counts = defaultdict(int)
        for a in alerts:
            counts[a.rule_name] += 1
        t = Table(box=box.MINIMAL, header_style="bold cyan", title="[bold]Top Rules[/]")
        t.add_column("Rule",  width=24)
        t.add_column("Count", justify="right", width=6)
        for rule, cnt in sorted(counts.items(), key=lambda x: -x[1])[:8]:
            t.add_row(rule, str(cnt))
        return t

    def render(self):
        layout = Layout()
        layout.split_column(
            Layout(self._header(),      name="header", size=3),
            Layout(name="body"),
        )
        layout["body"].split_row(
            Layout(self._alert_table(), name="alerts",  ratio=3),
            Layout(name="sidebar",                      ratio=1),
        )
        layout["sidebar"].split_column(
            Layout(self._stats_panel(), name="stats"),
            Layout(self._rule_table(),  name="rules"),
        )
        return layout

    def run(self):
        with Live(
            self.render(), console=console,
            refresh_per_second=1 / self.refresh_rate,
            screen=True,
        ) as live:
            try:
                while True:
                    live.update(self.render())
                    time.sleep(self.refresh_rate)
            except KeyboardInterrupt:
                pass