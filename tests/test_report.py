"""Tests for report_generator.py and templates/report.html."""

from __future__ import annotations

import re
from datetime import timedelta
from pathlib import Path

import pandas as pd

from alerting import Alert, AlertType, Severity
from config import __version__
from report_generator import HTMLReportGenerator, generate_report, svg_hbar, svg_pie, svg_timeline
from tests.conftest import BASE, make_df


def sample_alerts():
    return [
        Alert(BASE + timedelta(seconds=10), AlertType.DNS_TUNNELING, Severity.HIGH, "10.0.0.44",
              "192.168.1.53", "Possible DNS tunneling: 130 queries"),
        Alert(BASE + timedelta(seconds=20), AlertType.ML_ANOMALY, Severity.LOW, "10.0.0.9",
              "8.8.8.8", "<script>alert('xss')</script>"),
        Alert(BASE + timedelta(seconds=30), AlertType.BEACONING, Severity.MEDIUM, "10.0.0.51",
              "203.0.113.150", "Possible C2 beaconing"),
    ]


def test_context_counts(benign_df: pd.DataFrame) -> None:
    ctx = HTMLReportGenerator().build_context(benign_df, sample_alerts(), source="logs.csv",
                                              parse_stats={"total_rows": 205, "invalid_rows": 5})
    s = ctx["summary"]
    assert (s["records"], s["total_rows"], s["invalid_rows"]) == (200, 205, 5)
    assert (s["alerts"], s["high"], s["medium"], s["low"]) == (3, 1, 1, 1)
    assert (s["rule_alerts"], s["ml_alerts"]) == (2, 1)
    assert ctx["version"] == __version__
    assert [a["severity"] for a in ctx["alerts"]] == ["HIGH", "MEDIUM", "LOW"]
    assert set(ctx["charts"]) == {"timeline", "protocols", "talkers", "methods", "types"}


def test_rendered_html_is_self_contained(tmp_path: Path, benign_df: pd.DataFrame, isolated_config) -> None:
    path = HTMLReportGenerator(isolated_config).write(None, benign_df, sample_alerts(), source="logs.csv",
                                                      warnings=["feeds offline"])
    assert path == tmp_path / "report.html"
    html = path.read_text(encoding="utf-8")
    assert html.lstrip().lower().startswith("<!doctype html")
    assert html.count("<svg") >= 5
    assert "DNS tunneling" in html and "C2 beaconing" in html and "feeds offline" in html
    # No external resources: no remote scripts, stylesheets or images.
    assert not re.search(r'<(script|link|img)[^>]+(src|href)=["\']https?://', html, re.I)
    # Alert text is HTML-escaped.
    assert "<script>alert('xss')</script>" not in html
    assert "&lt;script&gt;" in html


def test_empty_report(tmp_path: Path) -> None:
    path = generate_report(make_df([]), [], tmp_path / "empty.html")
    html = path.read_text(encoding="utf-8")
    assert "<svg" in html and "</html>" in html


def test_svg_helpers() -> None:
    assert svg_pie([("TCP", 3), ("UDP", 1)]).startswith("<svg")
    assert "TCP" in svg_hbar([("TCP", 3.0)])
    assert svg_timeline(sample_alerts()).startswith("<svg")
    assert "<svg" in svg_timeline([]) and "<svg" in svg_pie([])
