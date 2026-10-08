"""Regression tests for the v2.0.1 bug-fix pass."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from log_parser import LogParser, parse_log_file
from threat_intel import parse_feed

HEADER = "timestamp,src_ip,dst_ip,src_port,dst_port,protocol,packet_length\n"


def test_mixed_utc_offsets_do_not_crash() -> None:
    values = pd.Series(["2024-03-10T01:00:00-05:00", "2024-03-10T03:00:00-04:00"])
    parsed = LogParser._parse_timestamps(values, False)
    assert parsed.notna().all()
    assert parsed.iloc[0] == pd.Timestamp("2024-03-10 06:00:00")


def test_utf8_bom_header(tmp_path: Path) -> None:
    path = tmp_path / "bom.csv"
    path.write_text("\ufeff" + HEADER + "2024-01-01 10:00:00,10.0.0.1,10.0.0.2,1234,80,TCP,60\n",
                    encoding="utf-8")
    result = parse_log_file(path)
    assert result.valid_rows == 1
    assert "timestamp" in result.column_mapping


def test_parse_feed_rejects_default_route() -> None:
    assert parse_feed("0.0.0.0/0\n::/0\n1.2.3.4\n") == ["1.2.3.4/32"]
