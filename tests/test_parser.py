"""Tests for log_parser.py: native CSV, malformed rows, public dataset profiles, chunking."""

from __future__ import annotations

import csv
from pathlib import Path

import pandas as pd
import pytest

from config import CONFIG, UNSW_NB15_COLUMNS
from log_parser import LogParseError, LogParser, iter_log_chunks, parse_log_file
from tests.conftest import background, write_native_csv


def test_valid_native_csv(native_csv: Path) -> None:
    result = parse_log_file(native_csv)
    assert result.total_rows == result.valid_rows == 200
    assert result.invalid_rows == 0 and result.errors == []
    assert result.profile == "default"
    assert list(result.data.columns) == list(CONFIG.schema.internal_columns)
    assert pd.api.types.is_datetime64_any_dtype(result.data["timestamp"])
    assert result.data["timestamp"].is_monotonic_increasing
    assert set(result.data["protocol"].astype(str)) == {"TCP", "UDP"}


def test_malformed_rows_are_rejected_with_line_numbers(tmp_path: Path, base_time) -> None:
    good = background(5)
    bad = [
        ["not-a-time", "10.0.0.1", "10.0.0.2", 1234, 80, "TCP", 100],    # bad timestamp
        [base_time, "999.1.1.1", "10.0.0.2", 1234, 80, "TCP", 100],      # bad IP
        [base_time, "10.0.0.1", "10.0.0.2", 1234, 70000, "TCP", 100],    # port out of range
        [base_time, "10.0.0.1", "10.0.0.2", 1234, 80, "XYZ", 100],       # unknown protocol
        [base_time, "10.0.0.1", "10.0.0.2", 1234, 80, "TCP", -5],        # negative length
        [base_time, "10.0.0.1", "10.0.0.2"],                             # too few fields
    ]
    path = write_native_csv(tmp_path / "mixed.csv", list(good) + bad)
    result = parse_log_file(path)

    assert result.valid_rows == 5
    assert result.total_rows == 11
    assert result.invalid_rows == 6
    assert sorted(e.line_number for e in result.errors) == list(range(7, 13))
    assert any("field count" in e.reason for e in result.errors)


def test_blank_lines_ignored(tmp_path: Path) -> None:
    path = write_native_csv(tmp_path / "blank.csv", background(3))
    path.write_text(path.read_text() + "\n\n,,,,,,\n")
    result = parse_log_file(path)
    assert result.valid_rows == 3 and result.invalid_rows == 0


def test_missing_and_empty_files(tmp_path: Path) -> None:
    with pytest.raises(LogParseError, match="not found"):
        parse_log_file(tmp_path / "nope.csv")
    empty = tmp_path / "empty.csv"
    empty.write_text("")
    with pytest.raises(LogParseError, match="empty"):
        parse_log_file(empty)


def test_unknown_profile_raises() -> None:
    with pytest.raises(ValueError, match="Unknown dataset profile"):
        LogParser(dataset_profile="bogus")


def test_cicids_auto_detection(tmp_path: Path) -> None:
    header = ["Flow ID", " Source IP", " Source Port", " Destination IP", " Destination Port",
              " Protocol", " Timestamp", " Flow Duration", "Total Length of Fwd Packets", " Label"]
    rows = [
        ["f1", "192.168.10.5", "51000", "8.8.8.8", "53", "17", "05/10/2026 08:00:01", "10", "64", "BENIGN"],
        ["f2", "192.168.10.5", "51001", "1.1.1.1", "443", "6", "05/10/2026 08:00:02", "10", "1200", "BENIGN"],
        ["f3", "192.168.10.6", "51002", "1.1.1.1", "0", "0", "05/10/2026 08:00:03", "10", "0", "BENIGN"],
    ]
    path = tmp_path / "cicids.csv"
    with path.open("w", newline="") as fh:
        csv.writer(fh).writerows([header, *rows])

    result = parse_log_file(path, dataset_profile="auto")
    assert result.profile == "cicids" and result.auto_detected
    assert result.valid_rows == 3
    df = result.data
    assert list(df["protocol"].astype(str)) == ["UDP", "TCP", "HOPOPT"]
    # Day-first timestamps: 05/10 is 5 October.
    assert df["timestamp"].iloc[0] == pd.Timestamp("2026-10-05 08:00:01")
    assert df["packet_length"].tolist() == [64, 1200, 0]


def test_unsw_headerless_auto_detection(tmp_path: Path) -> None:
    def row(i: int) -> list:
        values = {c: "0" for c in UNSW_NB15_COLUMNS}
        values.update(srcip="175.45.176.1", sport=str(40000 + i), dstip="149.171.126.6",
                      dsport="80", proto="tcp", state="FIN", service="http", sbytes=str(500 + i),
                      Stime=str(1421927414 + i), Ltime=str(1421927415 + i), attack_cat="", Label="0")
        return [values[c] for c in UNSW_NB15_COLUMNS]

    path = tmp_path / "UNSW-NB15_1.csv"
    with path.open("w", newline="") as fh:
        csv.writer(fh).writerows(row(i) for i in range(4))

    result = parse_log_file(path, dataset_profile="auto")
    assert result.profile == "unsw" and result.headerless
    assert result.valid_rows == 4
    assert result.data["dst_port"].tolist() == [80] * 4
    assert result.data["packet_length"].tolist() == [500, 501, 502, 503]


def test_custom_mapping(tmp_path: Path) -> None:
    path = tmp_path / "custom.csv"
    path.write_text("ts,src,dst,sp,dp,proto,len\n"
                    "2026-10-05 08:00:00,10.0.0.1,10.0.0.2,1000,22,tcp,60\n")
    mapping = {"ts": "timestamp", "src": "source_ip", "dst": "destination_ip", "sp": "source_port",
               "dp": "destination_port", "proto": "protocol", "len": "packet_length"}
    result = parse_log_file(path, dataset_profile="custom", column_mapping=mapping)
    assert result.valid_rows == 1
    assert result.data["protocol"].astype(str).iloc[0] == "TCP"


def test_iter_chunks_matches_full_parse(tmp_path: Path) -> None:
    path = write_native_csv(tmp_path / "logs.csv", background(230))
    chunks = list(iter_log_chunks(path, chunk_size=50))
    assert [c.total_rows for c in chunks] == [50, 50, 50, 50, 30]
    combined = pd.concat([c.data for c in chunks], ignore_index=True)
    full = parse_log_file(path).data
    pd.testing.assert_frame_equal(combined.reset_index(drop=True), full, check_categorical=False)


def test_iter_chunks_rejects_bad_size(native_csv: Path) -> None:
    with pytest.raises(ValueError):
        list(iter_log_chunks(native_csv, chunk_size=0))
