"""Tests for streaming.py: chunked processing must match batch results."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from alerting import Alert, AlertType, Severity
from detection_engine import DetectionEngine
from log_parser import parse_log_file
from mock_data_generator import MockDataGenerator
from streaming import StreamingProcessor, deduplicate_alerts
from tests.conftest import BASE, background, write_native_csv


def signature(alerts):
    """Order-independent identity of an alert list."""
    return sorted((a.alert_type.value, a.severity.value, a.source_ip, a.dest_ip) for a in alerts)


@pytest.fixture(scope="module")
def mock_csv(tmp_path_factory) -> Path:
    path = tmp_path_factory.mktemp("stream") / "logs.csv"
    MockDataGenerator(seed=7).write_csv(path, total_rows=3000)
    return path


@pytest.mark.parametrize("chunk_size", [400, 1500])
def test_streaming_matches_batch(mock_csv: Path, chunk_size: int) -> None:
    batch = DetectionEngine().run(parse_log_file(mock_csv).data)
    streamed = StreamingProcessor(chunk_size=chunk_size).process(mock_csv)

    assert signature(streamed.detection.rule_alerts) == signature(batch.rule_alerts)
    # File is below the ML warm-up size, so the ML result equals a batch run.
    assert signature(streamed.detection.ml_alerts) == signature(batch.ml_alerts)
    types = {a.alert_type for a in streamed.detection.alerts}
    assert {AlertType.PORT_SCAN, AlertType.BRUTE_FORCE, AlertType.BLACKLISTED_IP, AlertType.DNS_TUNNELING,
            AlertType.BEACONING, AlertType.TIME_OF_DAY_ANOMALY, AlertType.ML_ANOMALY} <= types
    assert streamed.chunks == -(-streamed.total_rows // chunk_size)


def test_row_counts_and_keep_data(mock_csv: Path) -> None:
    batch = parse_log_file(mock_csv)
    streamed = StreamingProcessor(chunk_size=700).process(mock_csv, keep_data=True)
    assert (streamed.total_rows, streamed.valid_rows, streamed.invalid_rows) == \
        (batch.total_rows, batch.valid_rows, batch.invalid_rows)
    assert len(streamed.data) == batch.valid_rows
    assert StreamingProcessor(chunk_size=700).process(mock_csv).data is None


def test_attack_straddling_chunk_boundary(tmp_path: Path) -> None:
    rows = background(100, span=60.0)
    scan_start = rows[-1][0] + timedelta(seconds=1)
    rows += [(scan_start + timedelta(seconds=0.1 * i), "203.0.113.9", "192.168.1.200", 40000 + i, 1 + i, "TCP", 60)
             for i in range(20)]
    rows += background(100, start=scan_start + timedelta(seconds=5), span=60.0)
    path = write_native_csv(tmp_path / "boundary.csv", rows)  # scan occupies rows 101-120

    engine = DetectionEngine(enable_ml=False)
    result = StreamingProcessor(engine=engine, chunk_size=110, overlap_rows=50).process(path)
    scans = [a for a in result.detection.alerts if a.alert_type is AlertType.PORT_SCAN]
    assert len(scans) == 1 and scans[0].details["unique_ports"] == 20


def test_deduplicate_alerts() -> None:
    def scan(start: int, end: int, sev: Severity) -> Alert:
        return Alert(BASE + timedelta(seconds=start), AlertType.PORT_SCAN, sev, "1.2.3.4", "5.6.7.8", "scan",
                     {"first_seen": str(BASE + timedelta(seconds=start)),
                      "last_seen": str(BASE + timedelta(seconds=end))})

    merged = deduplicate_alerts([scan(0, 3, Severity.MEDIUM), scan(2, 6, Severity.HIGH), scan(600, 602, Severity.MEDIUM)])
    assert len(merged) == 2
    first = min(merged, key=lambda a: a.timestamp)
    assert first.severity is Severity.HIGH and first.timestamp == BASE
    assert first.details["merged_alerts"] == 2
    assert first.details["last_seen"] == str(BASE + timedelta(seconds=6))


def test_invalid_chunk_size() -> None:
    with pytest.raises(ValueError):
        StreamingProcessor(chunk_size=-5)
