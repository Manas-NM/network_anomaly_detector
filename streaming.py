"""
streaming.py - Chunked (streaming) processing for large CSV logs.

:class:`StreamingProcessor` reads a log in fixed-size chunks with
:meth:`log_parser.LogParser.iter_chunks` and runs detection chunk by chunk,
so files far larger than memory can be analysed.

How attacks that straddle a chunk boundary are still caught
-----------------------------------------------------------
* **Sliding-window rules** (port scan, brute force, DNS tunneling) and the
  ML model run on ``overlap buffer + current chunk``. The buffer holds
  the last ``overlap_rows`` records of the previous window, so an attack that
  starts at the end of chunk *N* and continues into chunk *N+1* is seen in a
  single window.
* **Whole-capture detectors** (blacklist / threat intel, beaconing,
  time-of-day) need the full history of a host pair / source. They receive a
  compact projection of every chunk (only rows touching a listed host for the
  blacklist, 5 columns for beaconing, only the off-hours rows for
  time-of-day) and run once at the end, so their results equal batch mode.

Because chunks overlap, the same incident can be reported twice;
:func:`deduplicate_alerts` merges such duplicates (same type and hosts,
overlapping time range) into one alert.

**ML** needs a representative baseline: the first ``ml_warmup_rows`` records
(default 20,000) are collected, the Isolation Forest is trained and scored on
them once, and every later window is only *scored* against that baseline.
For files smaller than the warm-up size the ML result therefore equals a
batch run; for larger files it can differ slightly.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Tuple

import pandas as pd

from alerting import Alert, AlertType
from config import CONFIG, AppConfig, StreamingConfig
from detection_engine import DetectionEngine, DetectionResult, TimeOfDayDetector
from log_parser import LogParser, ProfileSpec, RowError

#: Columns kept for the end-of-stream beaconing pass.
_BEACON_COLUMNS = ["timestamp", "src_ip", "dst_ip", "dst_port", "packet_length"]


# --------------------------------------------------------------------------- #
# Alert de-duplication
# --------------------------------------------------------------------------- #
#: Types that are aggregated over the whole capture in batch mode: every
#: duplicate with the same key is merged regardless of time.
_MERGE_ALWAYS = {AlertType.BLACKLISTED_IP, AlertType.THREAT_INTEL_HIT, AlertType.ML_ANOMALY,
                 AlertType.BEACONING, AlertType.TIME_OF_DAY_ANOMALY}


def _alert_key(alert: Alert) -> Tuple:
    """Identity of an incident used to detect duplicates across chunks."""
    d = alert.details
    t = alert.alert_type
    if t in (AlertType.BLACKLISTED_IP, AlertType.THREAT_INTEL_HIT):
        return t, d.get("blacklisted_ip", alert.dest_ip), d.get("direction", "")
    if t is AlertType.BRUTE_FORCE:
        return t, alert.source_ip, alert.dest_ip, d.get("dst_port")
    if t in (AlertType.DNS_TUNNELING, AlertType.TIME_OF_DAY_ANOMALY):
        return t, alert.source_ip
    return t, alert.source_ip, alert.dest_ip


def _seen_range(alert: Alert) -> Tuple[datetime, datetime]:
    """``(first_seen, last_seen)`` from the alert details (fallback: timestamp)."""
    def parse(key: str) -> datetime:
        value = alert.details.get(key)
        try:
            return pd.Timestamp(value).to_pydatetime() if value else alert.timestamp
        except (ValueError, TypeError):
            return alert.timestamp
    return parse("first_seen"), parse("last_seen")


def deduplicate_alerts(alerts: List[Alert], config: AppConfig = CONFIG) -> List[Alert]:
    """Merge duplicate alerts produced by overlapping chunks.

    Two alerts are duplicates when they share :func:`_alert_key` and either
    belong to a capture-wide type (blacklist, threat intel, ML, beaconing,
    off-hours) or their ``first_seen``/``last_seen`` ranges overlap (allowing
    a gap of one detection window). The merged alert keeps the highest
    severity, the earliest timestamp and the widest time range, and records
    ``details["merged_alerts"]``.
    """
    gaps: Dict[AlertType, float] = {
        AlertType.PORT_SCAN: config.rules.port_scan_window_seconds,
        AlertType.BRUTE_FORCE: config.rules.brute_force_window_seconds,
        AlertType.DNS_TUNNELING: config.dns.window_seconds,
    }
    groups: Dict[Tuple, List[Alert]] = {}
    for alert in alerts:
        groups.setdefault(_alert_key(alert), []).append(alert)

    merged: List[Alert] = []
    for key, items in groups.items():
        items.sort(key=lambda a: _seen_range(a)[0])
        clusters: List[List[Alert]] = []
        cluster_end: Optional[datetime] = None
        gap = timedelta(seconds=gaps.get(key[0], 0.0))
        for alert in items:
            first, last = _seen_range(alert)
            if clusters and (key[0] in _MERGE_ALWAYS or (cluster_end and first <= cluster_end + gap)):
                clusters[-1].append(alert)
                cluster_end = max(cluster_end or last, last)
            else:
                clusters.append([alert])
                cluster_end = last
        for cluster in clusters:
            if len(cluster) == 1:
                merged.append(cluster[0])
                continue
            # Representative: highest severity, then the most evidence.
            best = max(cluster, key=lambda a: (a.severity.rank, len(str(a.details)), -a.timestamp.timestamp()))
            firsts, lasts = zip(*(_seen_range(a) for a in cluster))
            details = {**best.details, "first_seen": str(pd.Timestamp(min(firsts))),
                       "last_seen": str(pd.Timestamp(max(lasts))), "merged_alerts": len(cluster)}
            merged.append(replace(best, timestamp=min(a.timestamp for a in cluster), details=details))
    return merged


# --------------------------------------------------------------------------- #
# Streaming processor
# --------------------------------------------------------------------------- #
@dataclass
class StreamingResult:
    """Outcome of :meth:`StreamingProcessor.process`.

    Attributes:
        detection: Merged, de-duplicated detection result.
        source: Input path.
        total_rows: Rows read (valid + rejected) across all chunks.
        valid_rows: Rows that passed validation.
        errors: Rejected-row samples (capped at ``max_error_samples``).
        chunks: Number of chunks processed.
        profile / profile_description / auto_detected: Dataset profile used.
        data: All clean records (only when ``keep_data=True``), for the
            dashboard and HTML report.
    """

    detection: DetectionResult
    source: Path
    total_rows: int = 0
    valid_rows: int = 0
    errors: List[RowError] = field(default_factory=list)
    chunks: int = 0
    profile: str = "default"
    profile_description: str = ""
    auto_detected: bool = False
    data: Optional[pd.DataFrame] = None

    @property
    def invalid_rows(self) -> int:
        """Number of rejected rows."""
        return max(self.total_rows - self.valid_rows, len(self.errors))


class StreamingProcessor:
    """Chunk-by-chunk detection with an overlap buffer.

    Args:
        config: Application configuration (``config.streaming`` is used).
        engine: Detection engine to use (default: a new :class:`DetectionEngine`).
        chunk_size: Rows per chunk (default ``config.streaming.chunk_size``).
        overlap_rows: Rows carried over between chunks (default
            ``config.streaming.overlap_rows``).
    """

    def __init__(self, config: AppConfig = CONFIG, engine: Optional[DetectionEngine] = None,
                 chunk_size: Optional[int] = None, overlap_rows: Optional[int] = None) -> None:
        self.config = config
        self.cfg: StreamingConfig = config.streaming
        self.engine = engine or DetectionEngine(config)
        self.chunk_size = int(chunk_size or self.cfg.chunk_size)
        self.overlap_rows = int(self.cfg.overlap_rows if overlap_rows is None else overlap_rows)
        if self.chunk_size <= 0:
            raise ValueError(f"chunk_size must be positive, got {self.chunk_size}")

    @staticmethod
    def _concat(parts: List[pd.DataFrame]) -> pd.DataFrame:
        """Concatenate chunk frames and sort by timestamp."""
        return (pd.concat(parts, ignore_index=True).sort_values("timestamp", kind="mergesort")
                .reset_index(drop=True))

    def _window_detect(self, window: pd.DataFrame, result: DetectionResult) -> None:
        """Run the sliding-window detectors on one sorted ``buffer + chunk`` frame."""
        rules = self.engine.rule_detector
        start = time.perf_counter()
        result.rule_alerts.extend(rules.detect_port_scans(window))
        result.rule_alerts.extend(rules.detect_brute_force(window))
        result.timings["rules"] = result.timings.get("rules", 0.0) + time.perf_counter() - start
        result.rule_alerts.extend(self.engine.run_v2_detectors(window, result, names=["dns"]))

    def _blacklist_rows(self, data: pd.DataFrame) -> pd.DataFrame:
        """Rows of ``data`` involving a blacklisted / threat-intel host (usually very few)."""
        rules = self.engine.rule_detector
        ips = pd.unique(pd.concat([data["src_ip"], data["dst_ip"]]))
        bad = {ip for ip in ips if rules.is_blacklisted(str(ip)) or rules.intel_source(str(ip)) is not None}
        if not bad:
            return data.iloc[0:0]
        return data[data["src_ip"].isin(bad) | data["dst_ip"].isin(bad)]

    def _ml_detect(self, frame: pd.DataFrame, result: DetectionResult, refit: bool) -> None:
        """Fit (optionally) and score ``frame`` with the ML detector; errors become warnings."""
        ml = self.engine.ml_detector
        if ml is None or frame.empty:
            return
        start = time.perf_counter()
        try:
            ml_alerts, _ = ml.detect(frame, refit=refit)
            result.ml_alerts.extend(ml_alerts)
        except ValueError as exc:  # e.g. not enough records to train
            result.warnings.append(f"ML detection skipped: {exc}")
        result.timings["ml"] = result.timings.get("ml", 0.0) + time.perf_counter() - start

    def process(self, path: Path | str, dataset_profile: ProfileSpec = None,
                column_mapping: Optional[Mapping[str, str]] = None,
                keep_data: bool = False, max_error_samples: int = 1000) -> StreamingResult:
        """Stream ``path`` through the detectors.

        Raises:
            log_parser.LogParseError: If the file cannot be read at all.
        """
        parser = LogParser(self.config, max_error_samples=max_error_samples,
                           dataset_profile=dataset_profile, column_mapping=column_mapping)
        detection = DetectionResult()
        out = StreamingResult(detection=detection, source=Path(path))
        buffer = pd.DataFrame()
        blacklist_parts: List[pd.DataFrame] = []
        beacon_parts: List[pd.DataFrame] = []
        off_parts: List[pd.DataFrame] = []
        kept: List[pd.DataFrame] = []
        tod = TimeOfDayDetector(self.config)
        names = {name for name, _ in self.engine.v2_detectors}
        warmup: List[pd.DataFrame] = []
        ml_ready = False

        for chunk in parser.iter_chunks(path, self.chunk_size):
            out.chunks += 1
            out.total_rows += chunk.total_rows
            out.valid_rows += chunk.valid_rows
            room = max_error_samples - len(out.errors)
            if room > 0:
                out.errors.extend(chunk.errors[:room])
            out.profile, out.profile_description = chunk.profile, chunk.profile_description
            out.auto_detected = chunk.auto_detected
            data = chunk.data
            if data.empty:
                continue
            if keep_data:
                kept.append(data)
            blacklist_parts.append(self._blacklist_rows(data))
            if "beaconing" in names:
                beacon_parts.append(data[_BEACON_COLUMNS])
            if "time_of_day" in names:
                off_parts.append(data[tod.off_hours_mask(data["timestamp"])])

            window = data if buffer.empty else pd.concat([buffer, data], ignore_index=True)
            window = window.sort_values("timestamp", kind="mergesort").reset_index(drop=True)
            self._window_detect(window, detection)
            buffer = window.tail(self.overlap_rows) if self.overlap_rows > 0 else pd.DataFrame()

            # --- ML: learn the baseline from the first ml_warmup_rows, then score --- #
            if ml_ready:
                self._ml_detect(window, detection, refit=False)
            elif self.engine.ml_detector is not None:
                warmup.append(data)
                if sum(len(p) for p in warmup) >= self.cfg.ml_warmup_rows:
                    self._ml_detect(self._concat(warmup), detection, refit=True)
                    ml_ready, warmup = self.engine.ml_detector.is_fitted, []
        if warmup:  # stream ended before the warm-up size was reached
            self._ml_detect(self._concat(warmup), detection, refit=True)

        # --- whole-capture detectors on compact projections ----------------- #
        hits = [p for p in blacklist_parts if not p.empty]
        if hits:
            start = time.perf_counter()
            frame = pd.concat(hits, ignore_index=True).sort_values("timestamp", kind="mergesort")
            detection.rule_alerts.extend(self.engine.rule_detector.detect_blacklisted(frame))
            detection.timings["rules"] = detection.timings.get("rules", 0.0) + time.perf_counter() - start
        if beacon_parts:
            frame = pd.concat(beacon_parts, ignore_index=True).sort_values("timestamp", kind="mergesort")
            detection.rule_alerts.extend(self.engine.run_v2_detectors(frame, detection, names=["beaconing"]))
        if off_parts:
            frame = pd.concat(off_parts, ignore_index=True).sort_values("timestamp", kind="mergesort")
            detection.rule_alerts.extend(self.engine.run_v2_detectors(frame, detection, names=["time_of_day"]))

        detection.rule_alerts = deduplicate_alerts(detection.rule_alerts, self.config)
        detection.ml_alerts = DetectionEngine._corroborate(
            deduplicate_alerts(detection.ml_alerts, self.config), detection.rule_alerts)
        detection.alerts = sorted(detection.rule_alerts + detection.ml_alerts,
                                  key=lambda a: (a.timestamp, -a.severity.rank))
        detection.warnings = list(dict.fromkeys(detection.warnings))  # de-duplicate warnings
        if keep_data:
            out.data = (pd.concat(kept, ignore_index=True).sort_values("timestamp", kind="mergesort")
                        .reset_index(drop=True) if kept else pd.DataFrame())
        return out
