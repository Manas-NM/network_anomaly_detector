"""
alerting.py - Alert model, severity classification and persistent logging.

* :class:`Severity` and :class:`AlertType` enumerate the possible values
  (V2 adds DNS_TUNNELING, BEACONING, TIME_OF_DAY_ANOMALY and THREAT_INTEL_HIT).
* :class:`Alert` is an immutable record describing one detected incident.
* :class:`AlertManager` keeps an in-memory list of alerts, writes each one to
  ``alerts.log`` as a single formatted line, and offers summary helpers used
  by the dashboard and the CLI.

Example ``alerts.log`` line::

    2026-10-05 08:12:00.000 | HIGH   | PORT_SCAN      | 203.0.113.45 -> 192.168.1.10 | \
Port scan: 64 unique ports probed in 3.0s | {"unique_ports": 64, ...}
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from config import CONFIG, AppConfig


class Severity(str, Enum):
    """Alert severity levels (ordered LOW < MEDIUM < HIGH)."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    @property
    def rank(self) -> int:
        """Numeric rank for sorting/comparison (higher = more severe)."""
        return {"LOW": 1, "MEDIUM": 2, "HIGH": 3}[self.value]

    @property
    def color(self) -> str:
        """Rich colour style used to render this severity."""
        return {"LOW": "green", "MEDIUM": "yellow", "HIGH": "bold red"}[self.value]


class AlertType(str, Enum):
    """Categories of detections produced by the engine."""

    PORT_SCAN = "PORT_SCAN"
    BRUTE_FORCE = "BRUTE_FORCE"
    BLACKLISTED_IP = "BLACKLISTED_IP"
    ML_ANOMALY = "ML_ANOMALY"
    # --- V2 detectors ---------------------------------------------------- #
    DNS_TUNNELING = "DNS_TUNNELING"
    BEACONING = "BEACONING"
    TIME_OF_DAY_ANOMALY = "TIME_OF_DAY_ANOMALY"
    THREAT_INTEL_HIT = "THREAT_INTEL_HIT"

    @property
    def method(self) -> str:
        """Detection family: ``"ML"`` for the Isolation Forest, ``"Rule"`` otherwise."""
        return "ML" if self is AlertType.ML_ANOMALY else "Rule"

    @property
    def label(self) -> str:
        """Human-friendly name, e.g. ``DNS_TUNNELING`` -> ``"DNS tunneling"``."""
        return _ALERT_TYPE_LABELS.get(self.value, self.value.replace("_", " ").title())


_ALERT_TYPE_LABELS: Dict[str, str] = {
    "PORT_SCAN": "Port scan",
    "BRUTE_FORCE": "Brute force",
    "BLACKLISTED_IP": "Blacklisted IP",
    "ML_ANOMALY": "ML anomaly",
    "DNS_TUNNELING": "DNS tunneling",
    "BEACONING": "C2 beaconing",
    "TIME_OF_DAY_ANOMALY": "Off-hours activity",
    "THREAT_INTEL_HIT": "Threat intel hit",
}


@dataclass(frozen=True)
class Alert:
    """A single security alert.

    Attributes:
        timestamp: Time of the (first) offending network event.
        alert_type: Detection category.
        severity: LOW / MEDIUM / HIGH.
        source_ip: Originating address of the suspicious traffic.
        dest_ip: Destination address of the suspicious traffic.
        description: One-line human-readable summary.
        details: Structured, JSON-serialisable context (counts, ports, scores...).
        detected_at: Wall-clock time at which the alert was raised.
    """

    timestamp: datetime
    alert_type: AlertType
    severity: Severity
    source_ip: str
    dest_ip: str
    description: str
    details: Dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=datetime.now)

    def to_log_line(self) -> str:
        """Format the alert as a single pipe-delimited log line."""
        ts = self.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        details = json.dumps(self.details, default=str, sort_keys=True)
        return (
            f"{ts} | {self.severity.value:<6} | {self.alert_type.value:<14} | "
            f"{self.source_ip} -> {self.dest_ip} | {self.description} | {details}"
        )

    def to_dict(self) -> Dict[str, Any]:
        """JSON-friendly dictionary representation."""
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        data["detected_at"] = self.detected_at.isoformat()
        data["alert_type"] = self.alert_type.value
        data["severity"] = self.severity.value
        return data


class AlertManager:
    """Collects alerts in memory and persists them to ``alerts.log``.

    Args:
        log_path: Destination of the plain-text alert log.
        overwrite: When True (default) the log is truncated at start-up so each
            run produces a fresh report; when False new alerts are appended.
        config: Application configuration (used for the default path).
    """

    _LOGGER_NAME = "network_anomaly_detector.alerts"

    def __init__(self, log_path: Optional[Path] = None, overwrite: bool = True,
                 config: AppConfig = CONFIG) -> None:
        self.log_path = Path(log_path or config.paths.alerts_log)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._alerts: List[Alert] = []
        self._logger = self._build_logger(overwrite)

    # ------------------------------------------------------------------ #
    # Logger plumbing
    # ------------------------------------------------------------------ #
    def _build_logger(self, overwrite: bool) -> logging.Logger:
        """Create a dedicated file logger (isolated from the root logger)."""
        logger = logging.getLogger(f"{self._LOGGER_NAME}.{id(self)}")
        logger.setLevel(logging.INFO)
        logger.propagate = False
        for old in list(logger.handlers):  # id() can be reused: drop stale handlers
            old.close()
            logger.removeHandler(old)
        handler = logging.FileHandler(self.log_path, mode="w" if overwrite else "a", encoding="utf-8")
        # The alert line already contains the event timestamp and severity;
        # prefix only the detection time for auditability.
        handler.setFormatter(logging.Formatter("[%(asctime)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
        logger.addHandler(handler)
        return logger

    def close(self) -> None:
        """Flush and release the log file handle."""
        for handler in list(self._logger.handlers):
            handler.flush()
            handler.close()
            self._logger.removeHandler(handler)

    def __enter__(self) -> "AlertManager":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ #
    # Alert ingestion
    # ------------------------------------------------------------------ #
    def add_alert(self, alert: Alert) -> None:
        """Store ``alert`` and write it to the log at a matching logging level."""
        self._alerts.append(alert)
        level = {Severity.LOW: logging.INFO, Severity.MEDIUM: logging.WARNING,
                 Severity.HIGH: logging.CRITICAL}[alert.severity]
        self._logger.log(level, alert.to_log_line())

    def add_alerts(self, alerts: Iterable[Alert]) -> int:
        """Store several alerts (in chronological order). Returns the count added."""
        ordered = sorted(alerts, key=lambda a: a.timestamp)
        for alert in ordered:
            self.add_alert(alert)
        return len(ordered)

    # ------------------------------------------------------------------ #
    # Queries / summaries
    # ------------------------------------------------------------------ #
    @property
    def alerts(self) -> List[Alert]:
        """A copy of all stored alerts (chronological)."""
        return list(self._alerts)

    def filter(self, severity: Optional[Severity] = None,
               alert_type: Optional[AlertType] = None,
               min_severity: Optional[Severity] = None) -> List[Alert]:
        """Return alerts matching all supplied criteria."""
        result = self._alerts
        if severity is not None:
            result = [a for a in result if a.severity == severity]
        if alert_type is not None:
            result = [a for a in result if a.alert_type == alert_type]
        if min_severity is not None:
            result = [a for a in result if a.severity.rank >= min_severity.rank]
        return list(result)

    def count_by_severity(self) -> Dict[Severity, int]:
        """Alert count per severity (all levels present, even if zero)."""
        counts = Counter(a.severity for a in self._alerts)
        return {sev: counts.get(sev, 0) for sev in Severity}

    def count_by_type(self) -> Dict[AlertType, int]:
        """Alert count per type (all types present, even if zero)."""
        counts = Counter(a.alert_type for a in self._alerts)
        return {t: counts.get(t, 0) for t in AlertType}

    def recent(self, n: int = 10) -> List[Alert]:
        """The ``n`` most recent alerts by event timestamp (newest first)."""
        return sorted(self._alerts, key=lambda a: a.timestamp, reverse=True)[:n]

    def export_json(self, path: Path) -> Path:
        """Write all alerts as a JSON array to ``path`` and return the path."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps([a.to_dict() for a in self._alerts], indent=2, default=str),
                        encoding="utf-8")
        return path

    def __len__(self) -> int:
        return len(self._alerts)
