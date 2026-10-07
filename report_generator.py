"""
report_generator.py - Self-contained HTML security report.

:class:`HTMLReportGenerator` renders ``templates/report.html`` with Jinja2.
The resulting file has **no external dependencies**: CSS is inline and every
chart is an inline SVG generated here in Python, so the report can be e-mailed
or opened offline.

Sections
--------
* Executive summary - records analysed, alerts by severity, top threat types.
* Alert timeline - stacked bars per time bucket, coloured by severity.
* Protocol distribution - pie chart.
* Top talkers - horizontal bar chart of bytes sent per source IP.
* Detection method breakdown - rule-based vs ML alerts per type.
* Full alert table - every alert with severity colours.

Usage::

    from report_generator import HTMLReportGenerator
    HTMLReportGenerator().write("data/report.html", df, alerts, source="data/network_logs.csv")
"""

from __future__ import annotations

import math
from collections import Counter
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

import pandas as pd

from alerting import Alert, AlertType
from config import CONFIG, AppConfig, ReportConfig, __version__

#: Hex colours per severity (shared with the template legend).
SEVERITY_HEX: Dict[str, str] = {"HIGH": "#dc2626", "MEDIUM": "#f59e0b", "LOW": "#16a34a"}
#: Palette for categorical charts (protocols, alert types).
PALETTE: Tuple[str, ...] = ("#2563eb", "#7c3aed", "#0891b2", "#db2777", "#ea580c",
                            "#65a30d", "#4f46e5", "#0d9488", "#9333ea", "#64748b")


# --------------------------------------------------------------------------- #
# Inline SVG chart helpers
# --------------------------------------------------------------------------- #
def _empty_svg(message: str, width: int = 520, height: int = 160) -> str:
    """Placeholder SVG used when a chart has no data."""
    return (f'<svg viewBox="0 0 {width} {height}" class="chart" role="img">'
            f'<text x="{width / 2}" y="{height / 2}" text-anchor="middle" fill="#94a3b8">'
            f'{escape(message)}</text></svg>')


def svg_timeline(alerts: Sequence[Alert], buckets: int = 48, width: int = 960,
                 height: int = 240) -> str:
    """Stacked bar chart of alerts over time, one colour per severity."""
    if not alerts:
        return _empty_svg("No alerts", width, height)
    times = [a.timestamp.timestamp() for a in alerts]
    start, end = min(times), max(times)
    span = max(end - start, 1.0)
    buckets = max(1, min(buckets, len(alerts) * 2))
    counts = [Counter() for _ in range(buckets)]
    for alert, t in zip(alerts, times):
        idx = min(int((t - start) / span * buckets), buckets - 1)
        counts[idx][alert.severity.value] += 1
    peak = max(sum(c.values()) for c in counts) or 1
    left, bottom, top = 40, 30, 10
    plot_w, plot_h = width - left - 10, height - bottom - top
    bar_w = plot_w / buckets
    parts = [f'<svg viewBox="0 0 {width} {height}" class="chart" role="img" '
             f'aria-label="Alert timeline">']
    for frac in (0, 0.5, 1):  # grid + y labels
        y = top + plot_h * (1 - frac)
        parts.append(f'<line x1="{left}" y1="{y:.1f}" x2="{width - 10}" y2="{y:.1f}" stroke="#e2e8f0"/>'
                     f'<text x="{left - 6}" y="{y + 4:.1f}" text-anchor="end" class="axis">'
                     f'{round(peak * frac)}</text>')
    for i, c in enumerate(counts):
        y = top + plot_h
        x = left + i * bar_w
        for sev in ("LOW", "MEDIUM", "HIGH"):
            n = c.get(sev, 0)
            if not n:
                continue
            h = plot_h * n / peak
            y -= h
            label = datetime.fromtimestamp(start + span * i / buckets).strftime("%Y-%m-%d %H:%M")
            parts.append(f'<rect x="{x + 1:.1f}" y="{y:.1f}" width="{max(bar_w - 2, 1):.1f}" '
                         f'height="{h:.1f}" fill="{SEVERITY_HEX[sev]}"><title>{label}: {n} {sev}'
                         f'</title></rect>')
    for frac, anchor in ((0, "start"), (0.5, "middle"), (1, "end")):
        label = datetime.fromtimestamp(start + span * frac).strftime("%m-%d %H:%M:%S")
        parts.append(f'<text x="{left + plot_w * frac:.1f}" y="{height - 8}" text-anchor="{anchor}" '
                     f'class="axis">{label}</text>')
    parts.append("</svg>")
    return "".join(parts)


def svg_pie(items: Sequence[Tuple[str, float]], size: int = 220) -> str:
    """Pie chart with a legend; ``items`` are ``(label, value)`` pairs."""
    items = [(label, float(v)) for label, v in items if v > 0]
    total = sum(v for _, v in items)
    if not total:
        return _empty_svg("No data", size + 200, size)
    r, cx, cy = size / 2 - 10, size / 2, size / 2
    parts = [f'<svg viewBox="0 0 {size + 200} {size}" class="chart" role="img" aria-label="Pie chart">']
    angle = -math.pi / 2
    for i, (label, value) in enumerate(items):
        colour = PALETTE[i % len(PALETTE)]
        frac = value / total
        title = f"<title>{escape(label)}: {value:,.0f} ({frac:.1%})</title>"
        if frac >= 0.9999:
            parts.append(f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{colour}">{title}</circle>')
        else:
            end = angle + frac * 2 * math.pi
            x1, y1 = cx + r * math.cos(angle), cy + r * math.sin(angle)
            x2, y2 = cx + r * math.cos(end), cy + r * math.sin(end)
            large = 1 if frac > 0.5 else 0
            parts.append(f'<path d="M{cx},{cy} L{x1:.2f},{y1:.2f} A{r},{r} 0 {large} 1 {x2:.2f},{y2:.2f} Z" '
                         f'fill="{colour}" stroke="#fff" stroke-width="1">{title}</path>')
            angle = end
        ly = 20 + i * 22
        parts.append(f'<rect x="{size + 10}" y="{ly - 11}" width="12" height="12" fill="{colour}"/>'
                     f'<text x="{size + 28}" y="{ly}" class="legend">{escape(label)} '
                     f'({frac:.1%})</text>')
    parts.append("</svg>")
    return "".join(parts)


def svg_hbar(items: Sequence[Tuple[str, float]], width: int = 520, value_fmt: str = "{:,.0f}",
             colour: str = "#2563eb") -> str:
    """Horizontal bar chart; ``items`` are ``(label, value)`` pairs (largest first)."""
    if not items:
        return _empty_svg("No data", width)
    row_h, label_w = 24, 130
    height = row_h * len(items) + 10
    peak = max(v for _, v in items) or 1
    plot_w = width - label_w - 90
    parts = [f'<svg viewBox="0 0 {width} {height}" class="chart" role="img" aria-label="Bar chart">']
    for i, (label, value) in enumerate(items):
        y = 5 + i * row_h
        w = max(plot_w * value / peak, 1)
        parts.append(f'<text x="{label_w - 8}" y="{y + 15}" text-anchor="end" class="legend mono">'
                     f'{escape(str(label))}</text>'
                     f'<rect x="{label_w}" y="{y + 3}" width="{w:.1f}" height="{row_h - 8}" rx="3" '
                     f'fill="{colour}"/><text x="{label_w + w + 6:.1f}" y="{y + 15}" class="legend">'
                     f'{value_fmt.format(value)}</text>')
    parts.append("</svg>")
    return "".join(parts)


def _human_bytes(num: float) -> str:
    """Format a byte count (1536 -> '1.5 KB')."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024 or unit == "TB":
            return f"{num:,.0f} {unit}" if unit == "B" else f"{num:,.1f} {unit}"
        num /= 1024
    return f"{num:.1f} TB"


# --------------------------------------------------------------------------- #
# Report generator
# --------------------------------------------------------------------------- #
class HTMLReportGenerator:
    """Builds the self-contained HTML report.

    Args:
        config: Application configuration (``config.report`` is used).
    """

    def __init__(self, config: AppConfig = CONFIG) -> None:
        self.cfg: ReportConfig = config.report

    def _environment(self) -> Any:
        """Create the Jinja2 environment (autoescaping on)."""
        from jinja2 import Environment, FileSystemLoader, select_autoescape

        return Environment(loader=FileSystemLoader(str(self.cfg.template_dir)),
                           autoescape=select_autoescape(["html", "xml"]))

    def build_context(self, df: pd.DataFrame, alerts: Sequence[Alert], source: str = "",
                      parse_stats: Optional[Mapping[str, Any]] = None,
                      warnings: Optional[Sequence[str]] = None) -> Dict[str, Any]:
        """Compute every number and chart shown in the report."""
        alerts = sorted(alerts, key=lambda a: (a.timestamp, -a.severity.rank))
        stats = dict(parse_stats or {})
        sev_counts = Counter(a.severity.value for a in alerts)
        type_counts = Counter(a.alert_type for a in alerts)
        n = self.cfg.top_n

        if not df.empty:
            span = (df["timestamp"].max() - df["timestamp"].min()).total_seconds()
            first = df["timestamp"].min().strftime("%Y-%m-%d %H:%M:%S")
            last = df["timestamp"].max().strftime("%Y-%m-%d %H:%M:%S")
            protocols = df["protocol"].astype(str).value_counts()
            talkers = df.groupby("src_ip", observed=True)["packet_length"].sum().nlargest(n)
            total_bytes = int(df["packet_length"].sum())
            unique_src, unique_dst = int(df["src_ip"].nunique()), int(df["dst_ip"].nunique())
        else:
            span, first, last, total_bytes, unique_src, unique_dst = 0.0, "-", "-", 0, 0, 0
            protocols, talkers = pd.Series(dtype=int), pd.Series(dtype=int)

        proto_items = list(protocols.head(n - 1).items())
        if len(protocols) > n - 1:
            proto_items.append(("Other", int(protocols.iloc[n - 1:].sum())))

        alert_sources = Counter(a.source_ip for a in alerts)
        method_rows = []
        for t in AlertType:
            if type_counts.get(t):
                sev = Counter(a.severity.value for a in alerts if a.alert_type is t)
                method_rows.append({"type": t.value, "label": t.label, "method": t.method,
                                    "count": type_counts[t], "high": sev.get("HIGH", 0),
                                    "medium": sev.get("MEDIUM", 0), "low": sev.get("LOW", 0)})
        method_totals = Counter()
        for row in method_rows:
            method_totals[row["method"]] += row["count"]

        return {
            "title": self.cfg.title,
            "version": __version__,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source": str(source),
            "summary": {
                "records": len(df),
                "total_rows": stats.get("total_rows", len(df)),
                "invalid_rows": stats.get("invalid_rows", 0),
                "profile": stats.get("profile", ""),
                "first_seen": first, "last_seen": last,
                "span": f"{span / 60:,.1f} min" if span < 7200 else f"{span / 3600:,.1f} h",
                "total_bytes": _human_bytes(total_bytes),
                "unique_src": unique_src, "unique_dst": unique_dst,
                "alerts": len(alerts),
                "high": sev_counts.get("HIGH", 0), "medium": sev_counts.get("MEDIUM", 0),
                "low": sev_counts.get("LOW", 0),
                "rule_alerts": method_totals.get("Rule", 0), "ml_alerts": method_totals.get("ML", 0),
            },
            "top_threats": [{"label": t.label, "type": t.value, "count": c}
                            for t, c in type_counts.most_common(5)],
            "top_alert_sources": alert_sources.most_common(5),
            "method_rows": method_rows,
            "charts": {
                "timeline": svg_timeline(alerts, self.cfg.timeline_buckets),
                "protocols": svg_pie(proto_items),
                "talkers": svg_hbar([(ip, float(b)) for ip, b in talkers.items()],
                                    value_fmt="{:,.0f} B"),
                "methods": svg_pie([("Rule-based", method_totals.get("Rule", 0)),
                                    ("Machine learning", method_totals.get("ML", 0))]),
                "types": svg_hbar([(t.label, float(c)) for t, c in type_counts.most_common()],
                                  colour="#7c3aed"),
            },
            "alerts": [{
                "timestamp": a.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "severity": a.severity.value, "type": a.alert_type.value, "label": a.alert_type.label,
                "method": a.alert_type.method, "source": a.source_ip, "dest": a.dest_ip,
                "description": a.description,
            } for a in sorted(alerts, key=lambda a: (-a.severity.rank, a.timestamp))],
            "warnings": list(warnings or []),
            "severity_hex": SEVERITY_HEX,
        }

    def render(self, df: pd.DataFrame, alerts: Sequence[Alert], source: str = "",
               parse_stats: Optional[Mapping[str, Any]] = None,
               warnings: Optional[Sequence[str]] = None) -> str:
        """Return the report as an HTML string."""
        template = self._environment().get_template(self.cfg.template_name)
        return template.render(**self.build_context(df, alerts, source, parse_stats, warnings))

    def write(self, path: Optional[Path | str], df: pd.DataFrame, alerts: Sequence[Alert],
              source: str = "", parse_stats: Optional[Mapping[str, Any]] = None,
              warnings: Optional[Sequence[str]] = None) -> Path:
        """Render the report to ``path`` (default ``config.report.output_path``)."""
        target = Path(path or self.cfg.output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.render(df, alerts, source, parse_stats, warnings), encoding="utf-8")
        return target


def generate_report(df: pd.DataFrame, alerts: List[Alert], path: Optional[Path | str] = None,
                    source: str = "", parse_stats: Optional[Mapping[str, Any]] = None,
                    config: AppConfig = CONFIG) -> Path:
    """Convenience function: write the HTML report and return its path."""
    return HTMLReportGenerator(config).write(path, df, alerts, source, parse_stats)

