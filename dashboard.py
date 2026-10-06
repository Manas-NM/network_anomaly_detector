"""
dashboard.py - Rich-based terminal dashboard.

The dashboard renders four areas:

1. **Traffic summary** - packet/byte totals, unique IPs, capture window and
   protocol distribution.
2. **Alert breakdown** - counts by severity and by detection type, with bars.
3. **Top talkers** - most active source IPs, highlighting flagged hosts.
4. **Recent alerts** - newest alerts with colour-coded severity.

Two modes are offered:

* :meth:`Dashboard.render` - print a static snapshot once.
* :meth:`Dashboard.live_replay` - replay the capture chronologically inside a
  :class:`rich.live.Live` display so statistics and alerts "stream in".
"""

from __future__ import annotations

import time
from collections import Counter
from typing import Dict, List, Optional, Sequence

import pandas as pd
from rich import box
from rich.console import Console, Group, RenderableType
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from alerting import Alert, AlertType, Severity
from config import CONFIG, AppConfig

_BAR_WIDTH = 24


def _bar(value: int, maximum: int, style: str, width: int = _BAR_WIDTH) -> Text:
    """Return a horizontal bar proportional to ``value / maximum``."""
    filled = 0 if maximum <= 0 else max(1 if value else 0, round(width * value / maximum))
    return Text("█" * filled, style=style) + Text("░" * (width - filled), style="grey35")


def _human_bytes(num: float) -> str:
    """Format a byte count using binary units (KiB, MiB, ...)."""
    for unit in ("B", "KiB", "MiB", "GiB"):
        if abs(num) < 1024:
            return f"{num:,.1f} {unit}" if unit != "B" else f"{int(num):,} B"
        num /= 1024
    return f"{num:,.1f} TiB"


class Dashboard:
    """Builds Rich renderables summarising traffic and alerts.

    Args:
        config: Application configuration (``config.dashboard`` is used).
        console: Optional Rich console (a new one is created if omitted).
    """

    def __init__(self, config: AppConfig = CONFIG, console: Optional[Console] = None) -> None:
        self.cfg = config.dashboard
        self.console = console or Console()

    # ------------------------------------------------------------------ #
    # Individual panels
    # ------------------------------------------------------------------ #
    def summary_panel(self, df: pd.DataFrame, parse_stats: Optional[Dict[str, int]] = None) -> Panel:
        """Traffic statistics + protocol distribution."""
        stats = Table.grid(padding=(0, 2))
        stats.add_column(style="cyan", justify="left")
        stats.add_column(style="bold white", justify="right")

        total = len(df)
        stats.add_row("Total packets", f"{total:,}")
        if total:
            span = df["timestamp"].max() - df["timestamp"].min()
            stats.add_row("Total bytes", _human_bytes(float(df["packet_length"].sum())))
            stats.add_row("Avg packet size", f"{df['packet_length'].mean():,.0f} B")
            stats.add_row("Unique source IPs", f"{df['src_ip'].nunique():,}")
            stats.add_row("Unique dest IPs", f"{df['dst_ip'].nunique():,}")
            stats.add_row("Unique dest ports", f"{df['dst_port'].nunique():,}")
            stats.add_row("Capture start", df["timestamp"].min().strftime("%Y-%m-%d %H:%M:%S"))
            secs = int(span.total_seconds())
            stats.add_row("Capture span", f"{secs // 3600:02d}:{secs % 3600 // 60:02d}:{secs % 60:02d}")
        if parse_stats:
            stats.add_row("Rows rejected", f"{parse_stats.get('invalid', 0):,}")

        proto = Table(box=box.SIMPLE_HEAD, expand=True, title="Protocol distribution",
                      title_style="bold magenta")
        proto.add_column("Protocol", style="bold")
        proto.add_column("Packets", justify="right")
        proto.add_column("%", justify="right")
        proto.add_column("", ratio=1)
        if total:
            counts = df["protocol"].astype(str).value_counts()
            for name, count in counts.items():
                proto.add_row(name, f"{count:,}", f"{100 * count / total:.1f}",
                              _bar(int(count), int(counts.max()), "magenta"))

        return Panel(Group(stats, Text(""), proto), title="📊 Traffic Summary",
                     border_style="cyan", box=box.ROUNDED)

    def alert_breakdown_panel(self, alerts: Sequence[Alert]) -> Panel:
        """Alert counts by severity and by detection type."""
        sev_counts = Counter(a.severity for a in alerts)
        type_counts = Counter(a.alert_type for a in alerts)
        sev_max = max(sev_counts.values(), default=0)
        type_max = max(type_counts.values(), default=0)

        sev_table = Table(box=box.SIMPLE_HEAD, expand=True, title="By severity",
                          title_style="bold yellow")
        sev_table.add_column("Severity")
        sev_table.add_column("Count", justify="right")
        sev_table.add_column("", ratio=1)
        for sev in sorted(Severity, key=lambda s: -s.rank):
            n = sev_counts.get(sev, 0)
            sev_table.add_row(Text(sev.value, style=sev.color), str(n), _bar(n, sev_max, sev.color))

        type_table = Table(box=box.SIMPLE_HEAD, expand=True, title="By type",
                           title_style="bold yellow")
        type_table.add_column("Type")
        type_table.add_column("Count", justify="right")
        type_table.add_column("", ratio=1)
        for alert_type in AlertType:
            n = type_counts.get(alert_type, 0)
            type_table.add_row(alert_type.value, str(n), _bar(n, type_max, "yellow"))

        total = Text.assemble(("Total alerts: ", "bold"), (f"{len(alerts)}", "bold white"))
        return Panel(Group(total, sev_table, type_table), title="🚨 Alert Breakdown",
                     border_style="yellow", box=box.ROUNDED)

    def top_talkers_panel(self, df: pd.DataFrame, alerts: Sequence[Alert]) -> Panel:
        """Most active source IPs, with the number of alerts they triggered."""
        table = Table(box=box.SIMPLE_HEAD, expand=True)
        table.add_column("#", justify="right", style="dim")
        table.add_column("Source IP", style="bold")
        table.add_column("Packets", justify="right")
        table.add_column("Bytes", justify="right")
        table.add_column("Dst ports", justify="right")
        table.add_column("Alerts", justify="right")

        if not df.empty:
            alert_counts = Counter(a.source_ip for a in alerts)
            worst: Dict[str, Severity] = {}
            for a in alerts:
                if a.source_ip not in worst or a.severity.rank > worst[a.source_ip].rank:
                    worst[a.source_ip] = a.severity
            talkers = (df.groupby("src_ip", observed=True)
                         .agg(packets=("packet_length", "size"), bytes=("packet_length", "sum"),
                              ports=("dst_port", "nunique"))
                         .sort_values("packets", ascending=False)
                         .head(self.cfg.top_talkers))
            for rank, (ip, row) in enumerate(talkers.iterrows(), start=1):
                n_alerts = alert_counts.get(str(ip), 0)
                style = worst[str(ip)].color if n_alerts else "white"
                table.add_row(str(rank), Text(str(ip), style=style), f"{int(row.packets):,}",
                              _human_bytes(float(row.bytes)), f"{int(row.ports):,}",
                              Text(str(n_alerts), style=style))
        return Panel(table, title="🗣️  Top Talkers", border_style="green", box=box.ROUNDED)

    def recent_alerts_panel(self, alerts: Sequence[Alert]) -> Panel:
        """The newest alerts with colour-coded severity."""
        table = Table(box=box.SIMPLE_HEAD, expand=True, show_lines=False)
        table.add_column("Time", style="dim", no_wrap=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Type", no_wrap=True)
        table.add_column("Source", no_wrap=True)
        table.add_column("Destination", no_wrap=True)
        table.add_column("Description", ratio=1)

        recent = sorted(alerts, key=lambda a: (a.timestamp, a.severity.rank),
                        reverse=True)[: self.cfg.recent_alerts]
        for a in recent:
            table.add_row(a.timestamp.strftime("%H:%M:%S"), Text(a.severity.value, style=a.severity.color),
                          a.alert_type.value, a.source_ip, a.dest_ip, a.description)
        if not recent:
            table.add_row("-", Text("none", style="green"), "-", "-", "-", "No alerts raised 🎉")
        return Panel(table, title=f"🕒 Recent Alerts (latest {self.cfg.recent_alerts})",
                     border_style="red", box=box.ROUNDED)

    # ------------------------------------------------------------------ #
    # Composition
    # ------------------------------------------------------------------ #
    def build(self, df: pd.DataFrame, alerts: Sequence[Alert], title: str = "Network Anomaly Detector",
              subtitle: str = "", parse_stats: Optional[Dict[str, int]] = None) -> RenderableType:
        """Compose all panels into one renderable."""
        header = Panel(Text.assemble((f"🛡️  {title}", "bold white"), ("\n" + subtitle, "dim") if subtitle else ""),
                       box=box.HEAVY, border_style="bright_blue")
        top = Table.grid(expand=True, padding=(0, 1))
        top.add_column(ratio=1)
        top.add_column(ratio=1)
        top.add_row(self.summary_panel(df, parse_stats), self.alert_breakdown_panel(alerts))
        return Group(header, top, self.top_talkers_panel(df, alerts), self.recent_alerts_panel(alerts))

    def render(self, df: pd.DataFrame, alerts: Sequence[Alert], source: str = "",
               parse_stats: Optional[Dict[str, int]] = None) -> None:
        """Print a static dashboard snapshot to the console."""
        subtitle = f"Source: {source}" if source else ""
        self.console.print(self.build(df, alerts, subtitle=subtitle, parse_stats=parse_stats))

    def live_replay(self, df: pd.DataFrame, alerts: Sequence[Alert], source: str = "",
                    frames: Optional[int] = None, delay: Optional[float] = None) -> None:
        """Replay the capture chronologically, updating the dashboard live.

        The data are split into ``frames`` equal time slices. At each frame the
        dashboard shows only the traffic observed so far and the alerts whose
        event timestamp has already passed - simulating a live monitor.
        """
        frames = max(1, frames or self.cfg.live_frames)
        delay = self.cfg.live_frame_delay if delay is None else delay
        if df.empty:
            self.render(df, alerts, source)
            return

        df = df.sort_values("timestamp", kind="mergesort").reset_index(drop=True)
        start, end = df["timestamp"].iloc[0], df["timestamp"].iloc[-1]
        cutoffs: List[pd.Timestamp] = [start + (end - start) * (i / frames) for i in range(1, frames + 1)]
        times = df["timestamp"]

        with Live(console=self.console, refresh_per_second=12, transient=False) as live:
            for i, cutoff in enumerate(cutoffs, start=1):
                visible = df[times <= cutoff]
                seen = [a for a in alerts if pd.Timestamp(a.timestamp) <= cutoff]
                subtitle = (f"Source: {source}  •  replay {i}/{frames}  •  "
                            f"clock {cutoff.strftime('%H:%M:%S')}")
                live.update(self.build(visible, seen, title="Network Anomaly Detector — LIVE",
                                       subtitle=subtitle))
                time.sleep(delay)
