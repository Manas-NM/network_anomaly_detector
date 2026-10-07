"""
log_parser.py - Robust CSV network-log parser with external-dataset support.

Responsibilities
----------------
* Read a CSV log file in this tool's native format **or** in the format of a
  public IDS dataset (CICIDS2017, CSE-CIC-IDS2018, UNSW-NB15, or a custom
  mapping). Column presets live in :data:`config.COLUMN_MAPPING`.
* Auto-detect the dataset family from the header (``dataset_profile="auto"``),
  including the *headerless* UNSW-NB15_1..4.csv files.
* Strip whitespace from column names and rename them to internal snake_case
  names (``src_ip``, ``dst_port``, ...).
* Normalise values: numeric protocols -> names via
  :data:`config.PROTOCOL_NUMBER_MAP`, hex ports (``0x0050``) -> integers, Unix
  epoch timestamps -> datetimes.
* Validate every field and *drop* invalid rows instead of crashing, recording a
  human-readable reason for each rejected row.

The parser returns a :class:`ParseResult` containing a clean, typed
:class:`pandas.DataFrame` (sorted by timestamp), parsing statistics and the
dataset profile / column mapping that was applied.

V2: :meth:`LogParser.iter_chunks` / :func:`iter_log_chunks` read a large file
in fixed-size chunks for the streaming mode (``main.py --chunk-size``).
"""

from __future__ import annotations

import csv
import ipaddress
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional, Tuple, Union

import pandas as pd

from config import (
    CANONICAL_TO_INTERNAL,
    CONFIG,
    DATASET_PROFILES,
    PROFILE_ALIASES,
    PROTOCOL_NUMBER_MAP,
    AppConfig,
    DatasetProfile,
    make_custom_profile,
)

logger = logging.getLogger("network_anomaly_detector.parser")

#: Accepted values for ``dataset_profile``: a profile name, a ready-made
#: :class:`DatasetProfile`, a raw mapping dict (= custom profile) or None.
ProfileSpec = Union[str, DatasetProfile, Mapping[str, str], None]

#: Order in which auto-detection tries the built-in profiles.
_AUTO_CANDIDATES: Tuple[str, ...] = ("default", "cicids", "unsw")

#: Field values treated as "no port" by profiles with ``missing_port_as_zero``.
_PORT_PLACEHOLDERS = {"", "-", "nan", "none", "null"}


class LogParseError(Exception):
    """Raised when a log file cannot be parsed at all (missing file / header / columns)."""


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
    """Outcome of parsing a log file.

    Attributes:
        profile: Name of the dataset profile that was applied.
        profile_description: Human-readable profile name.
        auto_detected: True when the profile was chosen by auto-detection.
        headerless: True when the file had no header row (UNSW-NB15_1..4.csv).
        column_mapping: Source column (as written in the file) -> internal column.
    """

    data: pd.DataFrame
    source: Path
    total_rows: int = 0
    valid_rows: int = 0
    errors: List[RowError] = field(default_factory=list)
    profile: str = "default"
    profile_description: str = ""
    auto_detected: bool = False
    headerless: bool = False
    column_mapping: Dict[str, str] = field(default_factory=dict)

    @property
    def invalid_rows(self) -> int:
        """Number of rows that were rejected (exact, even when ``errors`` is truncated)."""
        return max(self.total_rows - self.valid_rows, len(self.errors))

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


def _normalise_name(name: str) -> str:
    """Column-name key used for matching: whitespace stripped, case-folded."""
    return str(name).strip().lstrip("\ufeff").strip().lower()


def _to_internal(target: str) -> Optional[str]:
    """Translate a canonical (``source_ip``) or internal (``src_ip``) name to internal."""
    key = target.strip().lower()
    if key in CANONICAL_TO_INTERNAL:
        return CANONICAL_TO_INTERNAL[key]
    return key if key in CANONICAL_TO_INTERNAL.values() else None


def resolve_profile(spec: ProfileSpec, column_mapping: Optional[Mapping[str, str]] = None
                    ) -> Optional[DatasetProfile]:
    """Turn a profile spec into a :class:`DatasetProfile` (None means auto-detect).

    Args:
        spec: ``"auto"``, ``"default"``, ``"cicids"``, ``"unsw"``, ``"custom"`` (or an
            alias such as ``"cicids2017"``), a :class:`DatasetProfile`, a mapping
            dict, or None (= native ``default`` format).
        column_mapping: Mapping used when ``spec == "custom"``.

    Raises:
        ValueError: For unknown profile names or an invalid custom mapping.
    """
    if isinstance(spec, DatasetProfile):
        return spec
    if isinstance(spec, Mapping):
        return make_custom_profile(spec)
    name = "default" if spec is None else PROFILE_ALIASES.get(spec.strip().lower(), spec.strip().lower())
    if name == "auto":
        return None
    if name == "custom":
        if not column_mapping:
            raise ValueError("dataset_profile='custom' requires a column_mapping dict")
        return make_custom_profile(column_mapping)
    if name not in DATASET_PROFILES:
        raise ValueError(f"Unknown dataset profile '{spec}'. Choose from: auto, custom, "
                         f"{', '.join(DATASET_PROFILES)}")
    return DATASET_PROFILES[name]


class LogParser:
    """Parses and validates CSV network logs.

    Args:
        config: Application configuration (schema definitions are used).
        max_error_samples: Upper bound on stored :class:`RowError` objects to
            avoid unbounded memory use on badly corrupted files. The total
            invalid count is always accurate.
        dataset_profile: Input format. ``None``/``"default"`` = native format,
            ``"auto"`` = detect from the header, ``"cicids"`` / ``"unsw"`` =
            public dataset presets, ``"custom"`` (with ``column_mapping``) or a
            mapping dict = user-defined columns.
        column_mapping: Source column -> canonical field mapping for
            ``dataset_profile="custom"``.
    """

    def __init__(self, config: AppConfig = CONFIG, max_error_samples: int = 1000,
                 dataset_profile: ProfileSpec = None,
                 column_mapping: Optional[Mapping[str, str]] = None) -> None:
        self.schema = config.schema
        self.max_error_samples = max_error_samples
        self.requested_profile = dataset_profile
        self.profile: Optional[DatasetProfile] = resolve_profile(dataset_profile, column_mapping)

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
            LogParseError: If the file does not exist, is empty, its format
                cannot be recognised, or required columns are missing.
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
            first = next(reader, None)
            if not first or not any(h.strip() for h in first):
                raise LogParseError(f"Log file is empty: {path}")

            profile, auto, header, headerless = self._select_profile(first, path)
            index_map, applied = self._map_columns(header, profile, path)
            wanted = [index_map[c] for c in self.schema.internal_columns]
            header_keys = [_normalise_name(h) for h in header]

            if headerless:  # the first line is already a data row
                good_rows.append([first[i] for i in wanted])
                line_numbers.append(1)

            for row in reader:
                if not row or not any(f.strip() for f in row):
                    continue  # ignore blank / all-empty lines (common at the end of CICIDS files)
                if len(row) != len(header):
                    structural_errors.append(RowError(
                        line_number=reader.line_num,
                        reason=f"wrong field count (expected {len(header)}, got {len(row)})",
                        raw=",".join(row)[:300],
                    ))
                    continue
                # Cheap first-field check before comparing the whole row.
                if (not headerless and _normalise_name(row[0]) == header_keys[0]
                        and [_normalise_name(f) for f in row] == header_keys):
                    # CSE-CIC-IDS2018 files repeat the header mid-file.
                    structural_errors.append(RowError(reader.line_num, "repeated header row",
                                                      ",".join(row)[:300]))
                    continue
                # Keep only the 7 needed fields: public datasets have 50-85 columns.
                good_rows.append([row[i] for i in wanted])
                line_numbers.append(reader.line_num)

        raw = pd.DataFrame(good_rows, columns=list(self.schema.internal_columns), dtype=str)
        raw["_line"] = line_numbers  # source line numbers for diagnostics

        clean, row_errors = self._validate(raw, profile)
        errors = sorted(structural_errors + row_errors, key=lambda e: e.line_number)

        return ParseResult(
            data=clean,
            source=path,
            total_rows=len(raw) + len(structural_errors),
            valid_rows=len(clean),
            errors=errors[: self.max_error_samples] if len(errors) > self.max_error_samples else errors,
            profile=profile.name,
            profile_description=profile.description,
            auto_detected=auto,
            headerless=headerless,
            column_mapping=applied,
        )

    # ------------------------------------------------------------------ #
    # V2: chunked reading (streaming mode)
    # ------------------------------------------------------------------ #
    def iter_chunks(self, path: Path | str, chunk_size: int = 5000) -> Iterator[ParseResult]:
        """Parse ``path`` lazily, yielding one :class:`ParseResult` per chunk.

        The same profile detection, column mapping and validation as
        :meth:`parse` are applied, but at most ``chunk_size`` raw rows are held
        in memory at a time. Each yielded result describes *only its chunk*
        (``total_rows``, ``valid_rows`` and ``errors`` are per chunk; line
        numbers refer to the whole file).

        Raises:
            LogParseError: Same conditions as :meth:`parse` (raised on the
                first ``next()``).
            ValueError: If ``chunk_size`` is not positive.
        """
        if chunk_size <= 0:
            raise ValueError(f"chunk_size must be positive, got {chunk_size}")
        path = Path(path)
        if not path.is_file():
            raise LogParseError(f"Log file not found: {path}")

        with path.open("r", newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.reader(fh, skipinitialspace=True)
            first = next(reader, None)
            if not first or not any(h.strip() for h in first):
                raise LogParseError(f"Log file is empty: {path}")
            profile, auto, header, headerless = self._select_profile(first, path)
            index_map, applied = self._map_columns(header, profile, path)
            wanted = [index_map[c] for c in self.schema.internal_columns]
            header_keys = [_normalise_name(h) for h in header]

            rows: List[List[str]] = []
            lines: List[int] = []
            structural: List[RowError] = []

            def flush() -> ParseResult:
                raw = pd.DataFrame(rows, columns=list(self.schema.internal_columns), dtype=str)
                raw["_line"] = lines
                clean, row_errors = self._validate(raw, profile)
                errors = sorted(structural + row_errors, key=lambda e: e.line_number)
                return ParseResult(
                    data=clean, source=path, total_rows=len(raw) + len(structural),
                    valid_rows=len(clean), errors=errors[: self.max_error_samples],
                    profile=profile.name, profile_description=profile.description,
                    auto_detected=auto, headerless=headerless, column_mapping=applied,
                )

            if headerless:
                rows.append([first[i] for i in wanted])
                lines.append(1)
            for row in reader:
                if not row or not any(f.strip() for f in row):
                    continue
                if len(row) != len(header):
                    structural.append(RowError(
                        reader.line_num,
                        f"wrong field count (expected {len(header)}, got {len(row)})",
                        ",".join(row)[:300]))
                elif (not headerless and _normalise_name(row[0]) == header_keys[0]
                        and [_normalise_name(f) for f in row] == header_keys):
                    structural.append(RowError(reader.line_num, "repeated header row",
                                               ",".join(row)[:300]))
                else:
                    rows.append([row[i] for i in wanted])
                    lines.append(reader.line_num)
                if len(rows) + len(structural) >= chunk_size:
                    yield flush()
                    rows, lines, structural = [], [], []
            if rows or structural:
                yield flush()

    # ------------------------------------------------------------------ #
    # Profile selection / column mapping
    # ------------------------------------------------------------------ #
    @staticmethod
    def _resolvable(header: List[str], profile: DatasetProfile) -> Dict[str, int]:
        """Return ``internal column -> header index`` for every field the profile can map."""
        positions: Dict[str, int] = {}
        for i, name in enumerate(header):
            positions.setdefault(_normalise_name(name), i)
        found: Dict[str, int] = {}
        for source, target in profile.column_mapping.items():
            internal = _to_internal(target)
            idx = positions.get(_normalise_name(source))
            if internal and idx is not None and internal not in found:
                found[internal] = idx
        return found

    @staticmethod
    def _signature_hits(header: List[str], profile: DatasetProfile) -> int:
        """Number of the profile's characteristic columns present in ``header``."""
        keys = {_normalise_name(h) for h in header}
        return sum(_normalise_name(c) in keys for c in profile.signature_columns)

    @staticmethod
    def _looks_headerless(first: List[str], profile: DatasetProfile) -> bool:
        """True if ``first`` is a data row of a headerless file for ``profile``."""
        return (bool(profile.headerless_columns) and len(first) == len(profile.headerless_columns)
                and _is_valid_ip(first[0]))

    def _select_profile(self, first: List[str], path: Path
                        ) -> Tuple[DatasetProfile, bool, List[str], bool]:
        """Pick the profile and header for the file.

        Returns:
            ``(profile, auto_detected, header, headerless)``.
        """
        required = set(self.schema.internal_columns)

        if self.profile is not None:  # explicit profile
            profile = self.profile
            if self._looks_headerless(first, profile):
                return profile, False, list(profile.headerless_columns), True
            return profile, False, first, False

        # --- auto-detection ---------------------------------------------- #
        unsw = DATASET_PROFILES["unsw"]
        if self._looks_headerless(first, unsw):
            logger.info("Auto-detected headerless UNSW-NB15 file: %s", path)
            return unsw, True, list(unsw.headerless_columns), True

        scored = []
        for name in _AUTO_CANDIDATES:
            candidate = DATASET_PROFILES[name]
            mapped = self._resolvable(first, candidate)
            scored.append((len(required & set(mapped)), self._signature_hits(first, candidate), name))
        # Prefer the profile that maps the most required fields, then the one
        # whose characteristic columns appear most often in the header.
        scored.sort(key=lambda t: (t[0], t[1]), reverse=True)
        best_fields, best_hits, best_name = scored[0]
        if best_fields == len(required):
            logger.info("Auto-detected dataset profile '%s' (%d signature columns) for %s",
                        best_name, best_hits, path)
            return DATASET_PROFILES[best_name], True, first, False

        # No profile fits completely: report the closest one's missing fields.
        best = DATASET_PROFILES[best_name]
        missing = sorted(required - set(self._resolvable(first, best)))
        raise LogParseError(
            f"Could not recognise the log format of {path}. Closest profile '{best_name}' "
            f"({best.description}) is missing: {self._describe_missing(missing, best)}. "
            f"Use --profile to force a format or supply a custom column mapping."
        )

    def _map_columns(self, header: List[str], profile: DatasetProfile, path: Path
                     ) -> Tuple[Dict[str, int], Dict[str, str]]:
        """Resolve header indices for every internal column and log the mapping.

        Returns:
            ``(internal column -> header index, source column -> internal column)``.
        """
        found = self._resolvable(header, profile)
        missing = [c for c in self.schema.internal_columns if c not in found]
        if missing:
            raise LogParseError(
                f"Log file is missing required columns for profile '{profile.name}' "
                f"({profile.description}): {self._describe_missing(missing, profile)}"
            )
        applied = {header[found[c]].strip(): c for c in self.schema.internal_columns}
        logger.info("Applied column mapping (profile '%s') for %s: %s", profile.name, path,
                    ", ".join(f"{src!r}->{dst}" for src, dst in applied.items()))
        return found, applied

    @staticmethod
    def _describe_missing(missing: List[str], profile: DatasetProfile) -> str:
        """Format missing internal columns with the source names the profile expects."""
        parts = []
        for col in missing:
            expected = [s.strip() for s, t in profile.column_mapping.items() if _to_internal(t) == col]
            parts.append(f"{col} (expected one of: {', '.join(repr(e) for e in expected[:4])})"
                         if expected else col)
        return "; ".join(parts)

    # ------------------------------------------------------------------ #
    # Value conversion / validation
    # ------------------------------------------------------------------ #
    @staticmethod
    def _parse_timestamps(values: pd.Series, dayfirst: bool) -> pd.Series:
        """Parse text dates (any format) and Unix epoch numbers (seconds or milliseconds)."""
        numeric = pd.to_numeric(values, errors="coerce")
        is_epoch = numeric.notna() & (numeric > 0)
        parts = []
        if is_epoch.any():
            epoch = numeric[is_epoch]
            seconds = epoch.where(epoch < 1e11, epoch / 1000.0)  # > 1e11 -> milliseconds
            parts.append(pd.to_datetime(seconds, unit="s", errors="coerce"))
        text = values[~is_epoch]
        if not text.empty:
            parsed = pd.to_datetime(text, errors="coerce", format="mixed", dayfirst=dayfirst)
            if getattr(parsed.dt, "tz", None) is not None:  # keep everything tz-naive
                parsed = parsed.dt.tz_convert(None)
            parts.append(parsed)
        if not parts:
            return pd.Series(pd.NaT, index=values.index, dtype="datetime64[ns]")
        return pd.concat(parts).reindex(values.index).astype("datetime64[ns]")

    @staticmethod
    def _parse_ports(values: pd.Series, missing_as_zero: bool) -> pd.Series:
        """Convert decimal or hex (``0x0050``) port strings to numbers (NaN if invalid)."""
        lowered = values.str.lower()
        is_hex = lowered.str.startswith("0x")
        ports = pd.to_numeric(values.where(~is_hex), errors="coerce")
        if is_hex.any():
            def _hex(v: str) -> float:
                try:
                    return float(int(v, 16))
                except ValueError:
                    return float("nan")
            ports[is_hex] = lowered[is_hex].map(_hex)
        if missing_as_zero:
            ports[lowered.isin(_PORT_PLACEHOLDERS)] = 0
        return ports

    @staticmethod
    def _normalise_protocols(values: pd.Series) -> pd.Series:
        """Upper-case names and map IANA protocol numbers (6, 17, 1, ...) to names."""
        proto = values.str.upper()
        numeric = proto.str.fullmatch(r"\d+(\.0+)?")
        if numeric.any():
            numbers = pd.to_numeric(proto[numeric]).astype(int)
            proto[numeric] = numbers.map(lambda n: PROTOCOL_NUMBER_MAP.get(n, f"PROTO-{n}"))
        return proto

    def _validate(self, df: pd.DataFrame, profile: DatasetProfile
                  ) -> tuple[pd.DataFrame, List[RowError]]:
        """Vectorised field conversion and validation.

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
        timestamps = self._parse_timestamps(df["timestamp"], profile.dayfirst)
        flag(timestamps.isna(), "invalid timestamp")

        # --- IP addresses -------------------------------------------------- #
        for col in ("src_ip", "dst_ip"):
            flag(~df[col].map(_is_valid_ip), f"invalid {col}")

        # --- Ports (0 allowed: ICMP has no ports) ------------------------- #
        ports: Dict[str, pd.Series] = {}
        for col in ("src_port", "dst_port"):
            ports[col] = self._parse_ports(df[col], profile.missing_port_as_zero)
            bad = ports[col].isna() | (ports[col] % 1 != 0) | (ports[col] < 0) | (ports[col] > 65535)
            flag(bad, f"invalid {col}")

        # --- Protocol ------------------------------------------------------ #
        protocol = self._normalise_protocols(df["protocol"])
        if profile.strict_protocols:
            flag(~protocol.isin(s.valid_protocols), "invalid protocol")
        else:
            flag(~protocol.str.fullmatch(r"[A-Z0-9][A-Z0-9_.\-]*"), "invalid protocol")

        # --- Packet length -------------------------------------------------- #
        min_len, max_len = profile.packet_length_bounds or (s.min_packet_length, s.max_packet_length)
        length = pd.to_numeric(df["packet_length"], errors="coerce")
        bad_len = length.isna() | (length % 1 != 0) | (length < min_len)
        if max_len is not None:
            bad_len |= length > max_len
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


def parse_log_file(path: Path | str, config: AppConfig = CONFIG, dataset_profile: ProfileSpec = None,
                   column_mapping: Optional[Mapping[str, str]] = None) -> ParseResult:
    """Convenience function: parse ``path`` with a :class:`LogParser`."""
    return LogParser(config, dataset_profile=dataset_profile, column_mapping=column_mapping).parse(path)


def iter_log_chunks(path: Path | str, chunk_size: int = 5000, config: AppConfig = CONFIG,
                    dataset_profile: ProfileSpec = None,
                    column_mapping: Optional[Mapping[str, str]] = None) -> Iterator[ParseResult]:
    """Convenience function: chunked iterator over ``path`` (see :meth:`LogParser.iter_chunks`)."""
    parser = LogParser(config, dataset_profile=dataset_profile, column_mapping=column_mapping)
    return parser.iter_chunks(path, chunk_size)


if __name__ == "__main__":  # pragma: no cover - manual smoke test
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    target: Optional[str] = sys.argv[1] if len(sys.argv) > 1 else str(CONFIG.paths.log_file)
    profile_arg: Optional[str] = sys.argv[2] if len(sys.argv) > 2 else "auto"
    result = parse_log_file(target, dataset_profile=profile_arg)
    print(f"Parsed {result.total_rows} rows from {result.source} [profile={result.profile}"
          f"{', auto' if result.auto_detected else ''}]: "
          f"{result.valid_rows} valid, {result.invalid_rows} invalid")
    for err in result.errors[:10]:
        print(f"  line {err.line_number}: {err.reason} -> {err.raw}")
