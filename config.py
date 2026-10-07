"""
config.py - Central configuration for the Network Log & Anomaly Detector.

Every tunable value (detection thresholds, blacklists, file paths, ML
hyper-parameters, dashboard settings) lives here so that the rest of the
code base never relies on "magic numbers".

The module also defines ``COLUMN_MAPPING`` / ``DATASET_PROFILES`` (column
presets for public IDS datasets such as CICIDS2017 and UNSW-NB15) and
``PROTOCOL_NUMBER_MAP`` (IANA protocol number -> name).

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
from typing import Dict, Mapping, Optional, Tuple

#: Application version (semantic versioning). Shown by ``main.py --version``.
__version__: str = "2.0.0"

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
# External dataset support: COLUMN_MAPPING
# --------------------------------------------------------------------------- #
# Public IDS datasets name their columns differently from this tool. Each preset
# below maps *source column name* -> *canonical field name*. Source names are
# matched case-insensitively once leading/trailing whitespace is stripped, so
# " Source IP" (CICIDS2017 puts a leading space on most headers) matches
# "Source IP" and "source ip". A preset may list several aliases for the same
# field; the first one present in the file wins.
#
# Canonical field names (left) and the internal DataFrame columns they become
# (right):
#     timestamp        -> timestamp
#     source_ip        -> src_ip
#     destination_ip   -> dst_ip
#     source_port      -> src_port
#     destination_port -> dst_port
#     protocol         -> protocol
#     packet_length    -> packet_length
CANONICAL_TO_INTERNAL: Dict[str, str] = {
    "timestamp": "timestamp",
    "source_ip": "src_ip",
    "destination_ip": "dst_ip",
    "source_port": "src_port",
    "destination_port": "dst_port",
    "protocol": "protocol",
    "packet_length": "packet_length",
}

COLUMN_MAPPING: Dict[str, Dict[str, str]] = {
    # CICIDS2017 ("GeneratedLabelledFlows" / "TrafficLabelling" CSVs) and
    # CSE-CIC-IDS2018 (CICFlowMeter output). Each row is one bidirectional flow;
    # packet_length is the total forward payload of the flow in bytes.
    "cicids": {
        " Timestamp": "timestamp",
        " Source IP": "source_ip",
        " Destination IP": "destination_ip",
        " Source Port": "source_port",
        " Destination Port": "destination_port",
        " Protocol": "protocol",
        " Total Length of Fwd Packets": "packet_length",
        # CSE-CIC-IDS2018 abbreviated header names (CICFlowMeter-V3).
        "Src IP": "source_ip",
        "Dst IP": "destination_ip",
        "Src Port": "source_port",
        "Dst Port": "destination_port",
        "TotLen Fwd Pkts": "packet_length",
    },
    # UNSW-NB15 (UNSW-NB15_1.csv ... UNSW-NB15_4.csv). "stime" is the flow start
    # time as Unix epoch seconds; packet_length is source->destination bytes.
    "unsw": {
        "stime": "timestamp",
        "srcip": "source_ip",
        "dstip": "destination_ip",
        "sport": "source_port",
        "dsport": "destination_port",
        "proto": "protocol",
        "sbytes": "packet_length",
    },
    # User-supplied mapping, e.g.
    #     LogParser(dataset_profile="custom",
    #               column_mapping={"ts": "timestamp", "src": "source_ip", ...})
    # or pass the dict directly: LogParser(dataset_profile={"ts": "timestamp", ...})
    "custom": {},
}

#: IANA IP protocol numbers -> names. Used to convert numeric "Protocol" values
#: (CICIDS stores 6/17/0) into the names used by this tool.
PROTOCOL_NUMBER_MAP: Dict[int, str] = {
    0: "HOPOPT",
    1: "ICMP",
    2: "IGMP",
    3: "GGP",
    4: "IPV4",       # IP-in-IP encapsulation
    6: "TCP",
    8: "EGP",
    9: "IGP",
    17: "UDP",
    27: "RDP-PROTO",  # Reliable Data Protocol (not Remote Desktop)
    41: "IPV6",
    43: "IPV6-ROUTE",
    44: "IPV6-FRAG",
    46: "RSVP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "IPV6-ICMP",
    59: "IPV6-NONXT",
    60: "IPV6-OPTS",
    88: "EIGRP",
    89: "OSPF",
    103: "PIM",
    112: "VRRP",
    115: "L2TP",
    132: "SCTP",
    136: "UDPLITE",
    137: "MPLS-IN-IP",
}

#: Column layout of the *headerless* UNSW-NB15_1..4.csv files (from
#: NUSW-NB15_features.csv). Used when such a file is detected.
UNSW_NB15_COLUMNS: Tuple[str, ...] = (
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes",
    "sttl", "dttl", "sloss", "dloss", "service", "Sload", "Dload", "Spkts", "Dpkts",
    "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz", "trans_depth",
    "res_bdy_len", "Sjit", "Djit", "Stime", "Ltime", "Sintpkt", "Dintpkt", "tcprtt",
    "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd",
    "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm",
    "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
    "attack_cat", "Label",
)


@dataclass(frozen=True)
class DatasetProfile:
    """How to read one dataset family.

    Attributes:
        name: Profile key (``default``, ``cicids``, ``unsw``, ``custom``).
        description: Human-readable name shown in the CLI output.
        column_mapping: Source column -> canonical/internal field name.
        signature_columns: Columns characteristic of the dataset; used by
            auto-detection to pick between profiles that both fit.
        dayfirst: Parse ambiguous dates as day/month (CICIDS uses d/m/Y).
        strict_protocols: If True only ``SchemaConfig.valid_protocols`` are
            accepted; otherwise any protocol name is kept (ARP, OSPF, ...).
        missing_port_as_zero: Treat ``-``/empty ports (ICMP, ARP flows) as 0
            instead of rejecting the row.
        packet_length_bounds: ``(min, max)`` override for packet_length; ``max``
            may be None (flow byte counts can exceed 65535). None = schema default.
        headerless_columns: Column names to use when the file has no header row.
    """

    name: str
    description: str
    column_mapping: Mapping[str, str]
    signature_columns: Tuple[str, ...] = ()
    dayfirst: bool = False
    strict_protocols: bool = True
    missing_port_as_zero: bool = False
    packet_length_bounds: Optional[Tuple[int, Optional[int]]] = None
    headerless_columns: Tuple[str, ...] = ()


def _default_mapping() -> Dict[str, str]:
    """Mapping for this tool's own CSV format (display, snake_case and canonical names)."""
    schema = SchemaConfig()
    mapping = dict(schema.column_map)
    mapping.update({c: c for c in schema.internal_columns})
    mapping.update({c: c for c in CANONICAL_TO_INTERNAL})
    return mapping


#: Built-in profiles selectable with ``--profile``.
DATASET_PROFILES: Dict[str, DatasetProfile] = {
    "default": DatasetProfile(
        name="default",
        description="Native format (mock_data_generator.py)",
        column_mapping=_default_mapping(),
        signature_columns=SchemaConfig().csv_headers,
    ),
    "cicids": DatasetProfile(
        name="cicids",
        description="CICIDS2017 / CSE-CIC-IDS2018 (CICFlowMeter flows)",
        column_mapping=COLUMN_MAPPING["cicids"],
        signature_columns=("Flow ID", "Flow Duration", "Total Fwd Packets", "Tot Fwd Pkts",
                           "Total Length of Fwd Packets", "TotLen Fwd Pkts", "Flow Bytes/s",
                           "Flow Byts/s", "Label"),
        dayfirst=True,
        strict_protocols=False,
        packet_length_bounds=(0, None),
    ),
    "unsw": DatasetProfile(
        name="unsw",
        description="UNSW-NB15 (Argus/Bro flows)",
        column_mapping=COLUMN_MAPPING["unsw"],
        signature_columns=("srcip", "dstip", "dsport", "sbytes", "dbytes", "stime", "ltime",
                           "attack_cat", "ct_srv_src"),
        strict_protocols=False,
        missing_port_as_zero=True,
        packet_length_bounds=(0, None),
        headerless_columns=UNSW_NB15_COLUMNS,
    ),
}

#: Profile names accepted by the parser / CLI (``auto`` triggers detection).
PROFILE_CHOICES: Tuple[str, ...] = ("auto", "cicids", "unsw", "default")

#: Friendly aliases accepted wherever a profile name is expected.
PROFILE_ALIASES: Dict[str, str] = {
    "cicids2017": "cicids",
    "cicids2018": "cicids",
    "cse-cic-ids2018": "cicids",
    "unsw-nb15": "unsw",
    "unswnb15": "unsw",
    "native": "default",
}


def make_custom_profile(mapping: Mapping[str, str], description: str = "Custom mapping",
                        **options: object) -> DatasetProfile:
    """Build a profile from a user mapping (source column -> canonical/internal name).

    Extra keyword ``options`` are forwarded to :class:`DatasetProfile` (e.g.
    ``dayfirst=True`` or ``strict_protocols=False``). Custom profiles are lenient
    about protocols and flow sizes by default because external data usually is.
    """
    unknown = sorted({v for v in mapping.values()}
                     - set(CANONICAL_TO_INTERNAL) - set(CANONICAL_TO_INTERNAL.values()))
    if unknown:
        raise ValueError(f"Unknown target field(s) in custom mapping: {', '.join(unknown)}. "
                         f"Valid targets: {', '.join(CANONICAL_TO_INTERNAL)}")
    defaults: Dict[str, object] = {"strict_protocols": False, "missing_port_as_zero": True,
                                   "packet_length_bounds": (0, None)}
    defaults.update(options)
    return DatasetProfile(name="custom", description=description, column_mapping=dict(mapping),
                          **defaults)  # type: ignore[arg-type]


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
    #: V2: also inject DNS tunneling, C2 beaconing and off-hours scenarios.
    include_v2_scenarios: bool = True


# --------------------------------------------------------------------------- #
# V2: DNS tunneling detection
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class DNSConfig:
    """Thresholds for :class:`detection_engine.DNSTunnelingDetector`.

    DNS tunnelling tools (iodine, dnscat2, ...) encode data in a stream of DNS
    queries, so an unusually high query *rate* from one host is a strong signal.
    """

    #: Destination port(s) treated as DNS.
    dns_ports: Tuple[int, ...] = (53,)
    #: Sliding window length in seconds.
    window_seconds: float = 60.0
    #: Alert (MEDIUM) when a source sends MORE than this many DNS queries in the window.
    query_threshold: int = 50
    #: Peak in-window query count strictly above which the alert is HIGH.
    high_severity_queries: int = 100


# --------------------------------------------------------------------------- #
# V2: Beaconing detection
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class BeaconingConfig:
    """Thresholds for :class:`detection_engine.BeaconingDetector`.

    Malware "phoning home" to a command-and-control (C2) server tends to connect
    at a fixed interval, so the *inter-arrival times* of a src->dst pair have a
    very low standard deviation compared with human-driven traffic.
    """

    #: A pair needs MORE than this many connections to be evaluated.
    min_connections: int = 10
    #: Alert (MEDIUM) when the std-dev of inter-arrival times is below this (seconds).
    max_interval_std_seconds: float = 2.0
    #: HIGH when the std-dev is below this value ...
    high_severity_std_seconds: float = 0.5
    #: ... and the pair has at least this many connections.
    high_severity_min_connections: int = 20
    #: Ignore pairs whose mean interval is shorter than this (seconds). Bursts such
    #: as brute force or port scans are regular too, but they are not beacons.
    min_mean_interval_seconds: float = 5.0
    #: Inter-arrival gaps below this (seconds) are treated as one connection
    #: (multiple packets of the same session) and collapsed.
    session_gap_seconds: float = 1.0


# --------------------------------------------------------------------------- #
# V2: Time-of-day anomaly detection
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class TimeOfDayConfig:
    """Thresholds for :class:`detection_engine.TimeOfDayDetector`.

    Business hours are ``[business_hours_start, business_hours_end)`` in the
    capture's local clock; everything else (default 22:00-06:00) is off-hours.
    """

    #: First business hour (0-23). Default 06:00.
    business_hours_start: int = 6
    #: First off-hours hour (0-24). Default 22:00.
    business_hours_end: int = 22
    #: Alert (MEDIUM) when one source makes MORE than this many off-hours connections.
    connection_threshold: int = 100
    #: Off-hours connection count strictly above which the alert is HIGH.
    high_severity_connections: int = 500


# --------------------------------------------------------------------------- #
# V2: Threat intelligence feeds
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ThreatFeedConfig:
    """Remote IP blocklists merged with ``RuleConfig.blacklisted_ips``.

    Fallback order when loading: fresh download -> cached copy -> static
    blacklist only. A cached copy younger than ``cache_ttl_hours`` is used
    without contacting the network (unless ``--update-feeds`` is given).
    """

    #: ``(feed name, URL)`` pairs. Each feed is a plain-text list, one IP/CIDR per line.
    feed_urls: Tuple[Tuple[str, str], ...] = (
        ("emerging_threats_compromised",
         "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"),
        ("abuse_ch_feodo_tracker",
         "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"),
    )
    #: Directory where downloaded feeds are cached.
    cache_dir: Path = DATA_DIR / "threat_feeds"
    #: Cached feeds older than this are refreshed from the network.
    cache_ttl_hours: float = 24.0
    #: HTTP timeout per feed (seconds).
    request_timeout_seconds: float = 10.0
    #: Optional local blocklist files (same format) merged in as extra feeds.
    local_feed_files: Tuple[Path, ...] = ()
    #: Set False to skip threat intel entirely (static blacklist only).
    enabled: bool = True


# --------------------------------------------------------------------------- #
# V2: PCAP input
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class PcapConfig:
    """Settings for :class:`pcap_parser.PcapParser`."""

    #: File extensions routed to the PCAP parser (lower-case).
    extensions: Tuple[str, ...] = (".pcap", ".pcapng", ".cap")
    #: Stop after this many packets (None = read everything).
    max_packets: Optional[int] = None
    #: Maximum number of skipped-packet samples kept for reporting.
    max_error_samples: int = 1000


# --------------------------------------------------------------------------- #
# V2: Streaming / chunked processing
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class StreamingConfig:
    """Settings for :class:`streaming.StreamingProcessor`."""

    #: Rows read and analysed per chunk.
    chunk_size: int = 5_000
    #: Rows from the end of the previous chunk carried into the next one so that
    #: attacks spanning a chunk boundary are still seen in a single window.
    overlap_rows: int = 2_000
    #: Records collected before the ML baseline is trained (later chunks are only
    #: scored). Training on a single small chunk would make the model too noisy.
    ml_warmup_rows: int = 20_000


# --------------------------------------------------------------------------- #
# V2: HTML report
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ReportConfig:
    """Settings for :class:`report_generator.HTMLReportGenerator`."""

    #: Default output path for ``--report``.
    output_path: Path = DATA_DIR / "report.html"
    #: Directory holding the Jinja2 template.
    template_dir: Path = BASE_DIR / "templates"
    #: Template file name inside ``template_dir``.
    template_name: str = "report.html"
    #: Number of entries shown in "top N" charts.
    top_n: int = 10
    #: Number of buckets in the alert timeline chart.
    timeline_buckets: int = 48
    #: Report title.
    title: str = "Network Log & Anomaly Detector - Security Report"


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
    # --- V2 sections --------------------------------------------------------- #
    dns: DNSConfig = field(default_factory=DNSConfig)
    beaconing: BeaconingConfig = field(default_factory=BeaconingConfig)
    time_of_day: TimeOfDayConfig = field(default_factory=TimeOfDayConfig)
    threat_feeds: ThreatFeedConfig = field(default_factory=ThreatFeedConfig)
    pcap: PcapConfig = field(default_factory=PcapConfig)
    streaming: StreamingConfig = field(default_factory=StreamingConfig)
    report: ReportConfig = field(default_factory=ReportConfig)


#: Default, shared configuration instance.
CONFIG: AppConfig = AppConfig()
