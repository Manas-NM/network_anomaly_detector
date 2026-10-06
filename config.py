"""
config.py - Central configuration for the Network Log & Anomaly Detector.

Every tunable value (detection thresholds, blacklists, file paths, ML
hyper-parameters, dashboard settings) lives here so that the rest of the
code base never relies on "magic numbers".

The configuration is expressed as a set of frozen dataclasses grouped under a
single :class:`AppConfig` object. Import the ready-made ``CONFIG`` instance for
default behaviour, or build a customised copy with :func:`dataclasses.replace`::

    from dataclasses import replace
    from config import CONFIG

    strict = replace(CONFIG, rules=replace(CONFIG.rules, port_scan_unique_ports=5))
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Tuple

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
#: Absolute path of the project root (directory containing this file).
BASE_DIR: Path = Path(__file__).resolve().parent

#: Directory holding generated / input log files.
DATA_DIR: Path = BASE_DIR / "data"


@dataclass(frozen=True)
class PathConfig:
    """File-system locations used by the application."""

    #: Default CSV log file consumed by the detector and written by the generator.
    log_file: Path = DATA_DIR / "network_logs.csv"
    #: Plain-text alert log (one formatted line per alert).
    alerts_log: Path = BASE_DIR / "alerts.log"
    #: Optional machine-readable export of all alerts.
    alerts_json: Path = DATA_DIR / "alerts.json"


# --------------------------------------------------------------------------- #
# Log schema
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class SchemaConfig:
    """Describes the CSV log format.

    ``csv_headers`` are the human readable column names written to / expected
    in the CSV file. ``column_map`` translates them into the snake_case names
    used internally throughout the code.
    """

    csv_headers: Tuple[str, ...] = (
        "Timestamp",
        "Source IP",
        "Destination IP",
        "Source Port",
        "Destination Port",
        "Protocol",
        "Packet Length",
    )
    internal_columns: Tuple[str, ...] = (
        "timestamp",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "packet_length",
    )
    #: Protocols accepted by the parser (upper-case).
    valid_protocols: Tuple[str, ...] = ("TCP", "UDP", "ICMP")
    #: Timestamp format used when *writing* logs (parsing is format-flexible).
    timestamp_format: str = "%Y-%m-%d %H:%M:%S.%f"
    #: Inclusive bounds for a valid packet length (bytes). 65535 = max IPv4 datagram.
    min_packet_length: int = 1
    max_packet_length: int = 65535

    @property
    def column_map(self) -> dict:
        """Mapping of CSV header -> internal column name."""
        return dict(zip(self.csv_headers, self.internal_columns))


# --------------------------------------------------------------------------- #
# Rule-based detection
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class RuleConfig:
    """Thresholds for the deterministic, rule-based detectors.

    A rule fires when the observed value is *strictly greater* than the
    threshold inside the sliding time window.
    """

    # --- Port scan: one source probing many ports on one destination -------- #
    #: Alert when a source touches MORE than this many unique ports ...
    port_scan_unique_ports: int = 10
    #: ... on a single destination within this many seconds.
    port_scan_window_seconds: float = 5.0
    #: Unique-port count at/above which a port scan is classified HIGH severity.
    port_scan_high_severity_ports: int = 50

    # --- Brute force: repeated connections to one service -------------------- #
    #: Alert when a source makes MORE than this many connections ...
    brute_force_connections: int = 20
    #: ... to the same destination service within this many seconds.
    brute_force_window_seconds: float = 10.0
    #: Peak in-window connection count at/above which brute force is HIGH severity.
    brute_force_high_severity_connections: int = 40
    #: Authentication-bearing services monitored for brute force. An empty
    #: tuple means "monitor every destination port".
    brute_force_ports: Tuple[int, ...] = (
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        110,   # POP3
        143,   # IMAP
        445,   # SMB
        1433,  # MSSQL
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        5900,  # VNC
    )

    # --- Blacklist ----------------------------------------------------------- #
    #: Known-malicious addresses. Entries may be single IPs or CIDR blocks.
    #: (RFC 5737 documentation ranges are used so no real host is implicated.)
    blacklisted_ips: Tuple[str, ...] = (
        "192.0.2.66",
        "192.0.2.99",
        "203.0.113.200",
        "198.51.100.128/28",
    )


# --------------------------------------------------------------------------- #
# Machine-learning detection
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class MLConfig:
    """Hyper-parameters for the Isolation Forest anomaly detector."""

    #: Expected proportion of anomalies in the data (0 < c <= 0.5).
    contamination: float = 0.03
    #: Number of trees in the forest.
    n_estimators: int = 300
    #: Samples drawn to train each tree ("auto" = min(256, n_samples)).
    max_samples: str | int = "auto"
    #: Seed for reproducible results.
    random_state: int = 42
    #: Rolling window (seconds) used to compute per-source frequency features.
    frequency_window_seconds: float = 10.0
    #: Feature columns fed to the model (engineered in detection_engine.py).
    feature_columns: Tuple[str, ...] = (
        "packet_length",        # raw size of the packet / flow record
        "src_conn_freq",        # records from the same source in the window
        "src_bytes_window",     # bytes sent by the same source in the window
        "pair_conn_freq",       # records for the same src->dst pair in the window
    )
    #: Isolation Forest ``decision_function`` scores below these values map to
    #: the corresponding severity (more negative = more anomalous).
    high_severity_score: float = -0.15
    medium_severity_score: float = -0.05
    #: Minimum number of records required before the model is trained.
    min_training_samples: int = 50


# --------------------------------------------------------------------------- #
# Dashboard
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class DashboardConfig:
    """Presentation settings for the Rich terminal dashboard."""

    top_talkers: int = 10
    recent_alerts: int = 15
    #: Number of replay frames rendered in --live mode.
    live_frames: int = 40
    #: Seconds between replay frames in --live mode.
    live_frame_delay: float = 0.15


# --------------------------------------------------------------------------- #
# Mock data generator
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class GeneratorConfig:
    """Defaults for the synthetic log generator."""

    total_rows: int = 10_000
    duration_seconds: int = 3_600
    random_seed: int = 1337
    #: Number of deliberately malformed rows (exercises parser robustness).
    malformed_rows: int = 7
    #: Start time of the generated capture (ISO format).
    start_time: str = "2026-10-05 08:00:00"


# --------------------------------------------------------------------------- #
# Aggregate config
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class AppConfig:
    """Top-level configuration object bundling every section."""

    paths: PathConfig = field(default_factory=PathConfig)
    schema: SchemaConfig = field(default_factory=SchemaConfig)
    rules: RuleConfig = field(default_factory=RuleConfig)
    ml: MLConfig = field(default_factory=MLConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    generator: GeneratorConfig = field(default_factory=GeneratorConfig)


#: Default, shared configuration instance.
CONFIG: AppConfig = AppConfig()
