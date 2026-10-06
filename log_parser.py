"""
log_parser.py - Robust CSV network-log parser.

Responsibilities
----------------
* Read a CSV log file whose header matches :class:`config.SchemaConfig`.
* Normalise column names to internal snake_case names.
* Validate every field (timestamp, IPv4/IPv6 addresses, port ranges,
  protocol, packet length) and *drop* invalid rows instead of crashing.
* Record a human-readable reason for each rejected row so problems with the
  input can be diagnosed.

The parser returns a :class:`ParseResult` containing a clean, typed
:class:`pandas.DataFrame` (sorted by timestamp) plus parsing statistics.
Helper :meth:`ParseResult.to_records` converts the frame into a list of
dicts for consumers that prefer plain Python structures.
"""

from __future__ import annotations

import csv
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

from config import CONFIG, AppConfig


class LogParseError(Exception):
    """Raised when a log file cannot be parsed at all (missing file / header)."""


@dataclass
class RowError:
    """Describes a single rejected input row.

    Attributes:
        line_number: 1-based line number in the source file (header = line 1).
        reason: Why the row was rejected.
        raw: The raw content of the row (best effort).
    """

    line_number: int
    reason: str
    raw: str = ""


@dataclass
class ParseResult:
    """Outcome of parsing a log file."""

    data: pd.DataFrame
    source: Path
    total_rows: int = 0
    valid_rows: int = 0
    errors: List[RowError] = field(default_factory=list)

    @property
    def invalid_rows(self) -> int:
        """Number of rows that were rejected."""
        return len(self.errors)

    def to_records(self) -> List[Dict[str, Any]]:
        """Return the valid rows as a list of plain dictionaries."""
        return self.data.to_dict(orient="records")


def _is_valid_ip(value: Any) -> bool:
    """Return ``True`` if ``value`` is a syntactically valid IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


class LogParser:
    """Parses and validates CSV network logs.

    Args:
        config: Application configuration (schema definitions are used).
        max_error_samples: Upper bound on stored :class:`RowError` objects to
            avoid unbounded memory use on badly corrupted files. The total
            invalid count is always accurate.
    """

    def __init__(self, config: AppConfig = CONFIG, max_error_samples: int = 1000) -> None:
        self.schema = config.schema
        self.max_error_samples = max_error_samples

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def parse(self, path: Path | str) -> ParseResult:
        """Parse ``path`` and return validated records.

        Args:
            path: CSV file to parse.

        Returns:
            :class:`ParseResult` with a clean DataFrame sorted by timestamp.

        Raises:
            LogParseError: If the file does not exist, is empty, or is missing
                required columns.
        """
        path = Path(path)
        if not path.is_file():
            raise LogParseError(f"Log file not found: {path}")

        structural_errors: List[RowError] = []
        good_rows: List[List[str]] = []
        line_numbers: List[int] = []

        # The csv module gives exact control over malformed lines: rows with
        # the wrong number of fields are recorded and skipped, never truncated.
        with path.open("r", newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.reader(fh, skipinitialspace=True)
            header = next(reader, None)
            if not header or not any(h.strip() for h in header):
                raise LogParseError(f"Log file is empty: {path}")
            for row in reader:
                if not row or not any(field.strip() for field in row):
                    continue  # ignore blank lines
                if len(row) != len(header):
                    structural_errors.append(RowError(
                        line_number=reader.line_num,
                        reason=f"wrong field count (expected {len(header)}, got {len(row)})",
                        raw=",".join(row),
                    ))
                    continue
                good_rows.append(row)
                line_numbers.append(reader.line_num)

        raw = pd.DataFrame(good_rows, columns=[h.strip() for h in header], dtype=str)
        raw = self._normalise_columns(raw)
        raw["_line"] = line_numbers  # source line numbers for diagnostics

        clean, row_errors = self._validate(raw)
        errors = sorted(structural_errors + row_errors, key=lambda e: e.line_number)

        return ParseResult(
            data=clean,
            source=path,
            total_rows=len(raw) + len(structural_errors),
            valid_rows=len(clean),
            errors=errors[: self.max_error_samples] if len(errors) > self.max_error_samples else errors,
        )

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #
    def _normalise_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        """Map CSV headers (case/whitespace-insensitive) to internal names."""
        lookup = {k.strip().lower(): v for k, v in self.schema.column_map.items()}
        # Also accept files that already use the internal snake_case names.
        lookup.update({c: c for c in self.schema.internal_columns})
        renamed = {col: lookup.get(str(col).strip().lower(), col) for col in df.columns}
        df = df.rename(columns=renamed)

        missing = [c for c in self.schema.internal_columns if c not in df.columns]
        if missing:
            raise LogParseError(f"Log file is missing required columns: {', '.join(missing)}")
        return df[list(self.schema.internal_columns)].copy()

    def _validate(self, df: pd.DataFrame) -> tuple[pd.DataFrame, List[RowError]]:
        """Vectorised field validation.

        Returns:
            ``(clean_frame, row_errors)``.
        """
        s = self.schema
        reasons = pd.Series("", index=df.index, dtype=object)

        def flag(mask: pd.Series, reason: str) -> None:
            """Append ``reason`` to every row where ``mask`` is True."""
            reasons.loc[mask] = reasons.loc[mask] + reason + "; "

        # Strip whitespace from all string fields.
        for col in s.internal_columns:
            df[col] = df[col].astype(str).str.strip()

        # --- Timestamp ---------------------------------------------------- #
        timestamps = pd.to_datetime(df["timestamp"], errors="coerce", format="mixed")
        flag(timestamps.isna(), "invalid timestamp")

        # --- IP addresses -------------------------------------------------- #
        for col in ("src_ip", "dst_ip"):
            flag(~df[col].map(_is_valid_ip), f"invalid {col}")

        # --- Ports (0 allowed: ICMP has no ports) ------------------------- #
        ports: Dict[str, pd.Series] = {}
        for col in ("src_port", "dst_port"):
            ports[col] = pd.to_numeric(df[col], errors="coerce")
            bad = ports[col].isna() | (ports[col] % 1 != 0) | (ports[col] < 0) | (ports[col] > 65535)
            flag(bad, f"invalid {col}")

        # --- Protocol ------------------------------------------------------ #
        protocol = df["protocol"].str.upper()
        flag(~protocol.isin(s.valid_protocols), "invalid protocol")

        # --- Packet length -------------------------------------------------- #
        length = pd.to_numeric(df["packet_length"], errors="coerce")
        bad_len = (length.isna() | (length % 1 != 0)
                   | (length < s.min_packet_length) | (length > s.max_packet_length))
        flag(bad_len, "invalid packet_length")

        invalid_mask = reasons != ""
        errors = [
            RowError(
                line_number=int(df.at[idx, "_line"]),
                reason=reasons.at[idx].rstrip("; "),
                raw=",".join(df.loc[idx, list(s.internal_columns)].astype(str)),
            )
            for idx in df.index[invalid_mask]
        ]

        valid = ~invalid_mask
        clean = pd.DataFrame(
            {
                "timestamp": timestamps[valid],
                "src_ip": df.loc[valid, "src_ip"],
                "dst_ip": df.loc[valid, "dst_ip"],
                "src_port": ports["src_port"][valid].astype("int32"),
                "dst_port": ports["dst_port"][valid].astype("int32"),
                "protocol": protocol[valid].astype("category"),
                "packet_length": length[valid].astype("int64"),
            }
        )
        clean = clean.sort_values("timestamp", kind="mergesort").reset_index(drop=True)
        return clean, errors


def parse_log_file(path: Path | str, config: AppConfig = CONFIG) -> ParseResult:
    """Convenience function: parse ``path`` with a default :class:`LogParser`."""
    return LogParser(config).parse(path)


if __name__ == "__main__":  # pragma: no cover - manual smoke test
    import sys

    target: Optional[str] = sys.argv[1] if len(sys.argv) > 1 else str(CONFIG.paths.log_file)
    result = parse_log_file(target)
    print(f"Parsed {result.total_rows} rows from {result.source}: "
          f"{result.valid_rows} valid, {result.invalid_rows} invalid")
    for err in result.errors[:10]:
        print(f"  line {err.line_number}: {err.reason} -> {err.raw}")
