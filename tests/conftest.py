"""
Shared pytest fixtures and helpers.

The project modules import each other by bare name (``from config import ...``),
so the project root is added to ``sys.path`` here. All fixtures are small and
built inline - no network access and no large files are needed.
"""

from __future__ import annotations

import csv
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import CONFIG  # noqa: E402

#: Fixed base time inside business hours (08:00-09:00 like the mock data).
BASE = datetime(2026, 10, 5, 8, 0, 0)

Row = Tuple[datetime, str, str, int, int, str, int]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def make_df(rows: Iterable[Row]) -> pd.DataFrame:
    """Build a DataFrame in the parser's internal schema from tuples."""
    df = pd.DataFrame(list(rows), columns=list(CONFIG.schema.internal_columns))
    df["timestamp"] = pd.to_datetime(df["timestamp"]).astype("datetime64[ns]")
    df = df.astype({"src_port": "int32", "dst_port": "int32", "packet_length": "int64"})
    df["protocol"] = df["protocol"].astype("category")
    return df.sort_values("timestamp", kind="mergesort").reset_index(drop=True)


def background(n: int = 200, start: datetime = BASE, span: float = 600.0) -> List[Row]:
    """Deterministic, benign background traffic (many clients, few requests each)."""
    rows: List[Row] = []
    for i in range(n):
        ts = start + timedelta(seconds=span * i / n)
        src = f"10.0.0.{2 + i % 50}"
        dst = f"192.168.1.{2 + (i * 7) % 20}"
        port, proto = [(443, "TCP"), (80, "TCP"), (53, "UDP"), (8080, "TCP")][i % 4]
        rows.append((ts, src, dst, 49152 + i, port, proto, 200 + (i * 37) % 1200))
    return rows


def write_native_csv(path: Path, rows: Sequence[Sequence[object]]) -> Path:
    """Write rows (already strings or datetimes) as a native-format CSV."""
    fmt = CONFIG.schema.timestamp_format
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(CONFIG.schema.csv_headers)
        for row in rows:
            writer.writerow([v.strftime(fmt) if isinstance(v, datetime) else v for v in row])
    return path


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture
def base_time() -> datetime:
    return BASE


@pytest.fixture
def benign_df() -> pd.DataFrame:
    return make_df(background())


@pytest.fixture
def native_csv(tmp_path: Path) -> Path:
    """Small valid native CSV (200 rows)."""
    return write_native_csv(tmp_path / "logs.csv", background())


@pytest.fixture
def isolated_config(tmp_path: Path):
    """CONFIG with feed cache and report output redirected into ``tmp_path``."""
    from dataclasses import replace

    feeds = replace(CONFIG.threat_feeds, cache_dir=tmp_path / "feeds")
    report = replace(CONFIG.report, output_path=tmp_path / "report.html")
    return replace(CONFIG, threat_feeds=feeds, report=report)
