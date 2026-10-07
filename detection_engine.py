"""
detection_engine.py - Rule-based and machine-learning anomaly detection.

Classes
-------
:class:`RuleBasedDetector`
    Deterministic detectors using *sliding time windows*:

    * **Port scan** - a source touching more than N unique destination ports
      on a single host within T seconds.
    * **Brute force** - a source opening more than N connections to the same
      authentication service (host + port) within T seconds.
    * **Blacklisted IP** - any traffic from/to an address or CIDR on the
      configured blacklist.

:class:`MLAnomalyDetector`
    An unsupervised Isolation Forest trained on packet size and
    connection-frequency features. It flags records that deviate from the
    learned traffic baseline (e.g. jumbo packets, sudden volume bursts).

V2 detectors
    * :class:`DNSTunnelingDetector` - an unusually high DNS query rate from
      one host (data exfiltration / C2 over DNS).
    * :class:`BeaconingDetector` - connections between a src->dst pair at a
      suspiciously regular interval (malware calling home).
    * :class:`TimeOfDayDetector` - heavy activity from one host outside
      business hours.
    * Threat-intel hits - :class:`RuleBasedDetector` accepts extra blacklist
      entries from :mod:`threat_intel` feeds.

:class:`DetectionEngine`
    Runs all detectors, cross-references their findings and returns a
    single, chronologically ordered :class:`DetectionResult`.

Each record in the log is treated as one connection / flow event.
"""

from __future__ import annotations

import ipaddress
import time
from collections import Counter
from dataclasses import dataclass, field, replace
from typing import Dict, Iterator, List, Mapping, Optional, Sequence, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from alerting import Alert, AlertType, Severity
from config import (CONFIG, AppConfig, BeaconingConfig, DNSConfig, MLConfig, RuleConfig,
                    TimeOfDayConfig)

_NS_PER_SECOND = 1_000_000_000


# --------------------------------------------------------------------------- #
# Sliding-window helper
# --------------------------------------------------------------------------- #
@dataclass
class WindowIncident:
    """A contiguous period during which a sliding-window rule was violated.

    Attributes:
        start_idx: Index (within the group arrays) of the first event in the
            window that first crossed the threshold.
        end_idx: Index of the last event that still violated the threshold.
        peak: Highest metric value (unique ports / connections) in any window.
    """

    start_idx: int
    end_idx: int
    peak: int


def sliding_window_incidents(times_ns: np.ndarray, values: np.ndarray, window_seconds: float,
                             threshold: int, count_unique: bool) -> List[WindowIncident]:
    """Find periods where a windowed metric exceeds ``threshold``.

    A two-pointer sliding window walks over events sorted by time. For each
    new event the left edge is advanced until the window spans at most
    ``window_seconds``. The metric is either the number of events in the
    window (``count_unique=False``) or the number of distinct ``values``
    (``count_unique=True``, e.g. unique destination ports).

    Consecutive violating windows - including those separated by less than
    one window length - are merged into a single :class:`WindowIncident` so
    one attack produces one alert instead of hundreds.

    Args:
        times_ns: Event timestamps as int64 nanoseconds, sorted ascending.
        values: Per-event values (only used when ``count_unique`` is True).
        window_seconds: Window length in seconds.
        threshold: The metric must be strictly greater than this value.
        count_unique: Count distinct values instead of events.

    Returns:
        List of incidents (possibly empty).
    """
    window_ns = int(window_seconds * _NS_PER_SECOND)
    counts: Counter = Counter()
    incidents: List[WindowIncident] = []
    current: Optional[WindowIncident] = None
    left = 0

    for right in range(len(times_ns)):
        counts[values[right]] += 1
        # Shrink window from the left until it spans <= window_ns.
        while times_ns[right] - times_ns[left] > window_ns:
            counts[values[left]] -= 1
            if counts[values[left]] == 0:
                del counts[values[left]]
            left += 1

        metric = len(counts) if count_unique else (right - left + 1)
        if metric > threshold:
            if current is None:
                # Merge with the previous incident if it ended within one window.
                prev = incidents[-1] if incidents else None
                if prev and times_ns[left] - times_ns[prev.end_idx] <= window_ns:
                    current = incidents.pop()
                else:
                    current = WindowIncident(start_idx=left, end_idx=right, peak=metric)
            current.end_idx = right
            current.peak = max(current.peak, metric)
        elif current is not None:
            incidents.append(current)
            current = None

    if current is not None:
        incidents.append(current)
    return incidents


# --------------------------------------------------------------------------- #
# Rule-based detection
# --------------------------------------------------------------------------- #
class RuleBasedDetector:
    """Signature/threshold based detectors (port scan, brute force, blacklist).

    Args:
        config: Application configuration (``config.rules`` is used).
        extra_blacklist: Optional V2 threat-intel entries (IP or CIDR -> feed
            name), e.g. from :meth:`threat_intel.ThreatIntelManager.load`.
            Matches that are *not* on the static blacklist are reported as
            ``THREAT_INTEL_HIT``; static matches stay ``BLACKLISTED_IP``.
    """

    def __init__(self, config: AppConfig = CONFIG,
                 extra_blacklist: Optional[Mapping[str, str]] = None) -> None:
        self.rules: RuleConfig = config.rules
        self._blacklist = [ipaddress.ip_network(e, strict=False) for e in self.rules.blacklisted_ips]
        self._blacklist_cache: Dict[str, bool] = {}
        # V2 threat intel: exact hosts in a dict (O(1) lookup), CIDR blocks in a list.
        self._intel_hosts: Dict[str, str] = {}
        self._intel_nets: List[Tuple[ipaddress._BaseNetwork, str]] = []
        self._intel_cache: Dict[str, Optional[str]] = {}
        if extra_blacklist:
            self.add_threat_intel(extra_blacklist)

    # ------------------------------------------------------------------ #
    # V2: threat-intel blacklist extension
    # ------------------------------------------------------------------ #
    def add_threat_intel(self, entries: Mapping[str, str]) -> int:
        """Extend the blacklist with ``{ip_or_cidr: feed_name}`` entries.

        Invalid entries are ignored. Returns the number of entries accepted.
        """
        accepted = 0
        for entry, source in entries.items():
            try:
                net = ipaddress.ip_network(str(entry).strip(), strict=False)
            except ValueError:
                continue
            if net.num_addresses == 1:
                self._intel_hosts[str(net.network_address)] = str(source)
            else:
                self._intel_nets.append((net, str(source)))
            accepted += 1
        self._intel_cache.clear()
        return accepted

    @property
    def threat_intel_size(self) -> int:
        """Number of threat-intel entries loaded."""
        return len(self._intel_hosts) + len(self._intel_nets)

    def intel_source(self, ip: str) -> Optional[str]:
        """Return the feed name listing ``ip``, or None (cached)."""
        if not self._intel_hosts and not self._intel_nets:
            return None
        if ip in self._intel_cache:
            return self._intel_cache[ip]
        source = self._intel_hosts.get(ip)
        if source is None and self._intel_nets:
            try:
                addr = ipaddress.ip_address(ip)
                source = next((src for net, src in self._intel_nets if addr in net), None)
            except ValueError:
                source = None
        self._intel_cache[ip] = source
        return source

    # ------------------------------------------------------------------ #
    def detect(self, df: pd.DataFrame) -> List[Alert]:
        """Run every rule against ``df`` and return all alerts."""
        if df.empty:
            return []
        df = df.sort_values("timestamp", kind="mergesort")
        return [*self.detect_port_scans(df), *self.detect_brute_force(df), *self.detect_blacklisted(df)]

    # ------------------------------------------------------------------ #
    @staticmethod
    def _groups(df: pd.DataFrame, keys: List[str]) -> Iterator[Tuple[tuple, pd.DataFrame]]:
        """Yield ``(key, group)`` pairs, each group sorted by timestamp."""
        for key, group in df.groupby(keys, sort=False, observed=True):
            yield (key if isinstance(key, tuple) else (key,)), group

    def detect_port_scans(self, df: pd.DataFrame) -> List[Alert]:
        """Detect sources probing > N unique ports on one host within T seconds."""
        r = self.rules
        # Cheap pre-filter: only pairs that ever touch > threshold distinct ports.
        nunique = df.groupby(["src_ip", "dst_ip"], observed=True)["dst_port"].nunique()
        suspects = nunique[nunique > r.port_scan_unique_ports].index
        if suspects.empty:
            return []
        candidate = df.set_index(["src_ip", "dst_ip"]).loc[suspects].reset_index()

        alerts: List[Alert] = []
        for (src, dst), group in self._groups(candidate, ["src_ip", "dst_ip"]):
            group = group.sort_values("timestamp", kind="mergesort")
            times = group["timestamp"].to_numpy(dtype="datetime64[ns]").astype(np.int64)
            ports = group["dst_port"].to_numpy()
            for inc in sliding_window_incidents(times, ports, r.port_scan_window_seconds,
                                                r.port_scan_unique_ports, count_unique=True):
                window = group.iloc[inc.start_idx: inc.end_idx + 1]
                unique_ports = sorted(int(p) for p in window["dst_port"].unique())
                duration = (window["timestamp"].iloc[-1] - window["timestamp"].iloc[0]).total_seconds()
                severity = (Severity.HIGH if len(unique_ports) >= r.port_scan_high_severity_ports
                            else Severity.MEDIUM)
                alerts.append(Alert(
                    timestamp=window["timestamp"].iloc[0].to_pydatetime(),
                    alert_type=AlertType.PORT_SCAN,
                    severity=severity,
                    source_ip=str(src),
                    dest_ip=str(dst),
                    description=(f"Port scan: {len(unique_ports)} unique ports probed in "
                                 f"{duration:.1f}s (threshold >{r.port_scan_unique_ports} "
                                 f"in {r.port_scan_window_seconds:g}s)"),
                    details={
                        "unique_ports": len(unique_ports),
                        "peak_ports_in_window": int(inc.peak),
                        "events": int(len(window)),
                        "duration_seconds": round(duration, 3),
                        "first_seen": str(window["timestamp"].iloc[0]),
                        "last_seen": str(window["timestamp"].iloc[-1]),
                        "sample_ports": unique_ports[:20],
                    },
                ))
        return alerts

    def detect_brute_force(self, df: pd.DataFrame) -> List[Alert]:
        """Detect > N connections to one service (host:port) within T seconds."""
        r = self.rules
        data = df[df["dst_port"].isin(r.brute_force_ports)] if r.brute_force_ports else df
        keys = ["src_ip", "dst_ip", "dst_port"]
        sizes = data.groupby(keys, observed=True).size()
        suspects = sizes[sizes > r.brute_force_connections].index
        if suspects.empty:
            return []
        candidate = data.set_index(keys).loc[suspects].reset_index()

        alerts: List[Alert] = []
        for (src, dst, port), group in self._groups(candidate, keys):
            group = group.sort_values("timestamp", kind="mergesort")
            times = group["timestamp"].to_numpy(dtype="datetime64[ns]").astype(np.int64)
            for inc in sliding_window_incidents(times, times, r.brute_force_window_seconds,
                                                r.brute_force_connections, count_unique=False):
                window = group.iloc[inc.start_idx: inc.end_idx + 1]
                duration = (window["timestamp"].iloc[-1] - window["timestamp"].iloc[0]).total_seconds()
                severity = (Severity.HIGH if inc.peak >= r.brute_force_high_severity_connections
                            else Severity.MEDIUM)
                alerts.append(Alert(
                    timestamp=window["timestamp"].iloc[0].to_pydatetime(),
                    alert_type=AlertType.BRUTE_FORCE,
                    severity=severity,
                    source_ip=str(src),
                    dest_ip=str(dst),
                    description=(f"Brute force on port {int(port)}: {len(window)} connections in "
                                 f"{duration:.1f}s (peak {inc.peak} in "
                                 f"{r.brute_force_window_seconds:g}s, threshold "
                                 f">{r.brute_force_connections})"),
                    details={
                        "dst_port": int(port),
                        "connections": int(len(window)),
                        "peak_connections_in_window": int(inc.peak),
                        "duration_seconds": round(duration, 3),
                        "first_seen": str(window["timestamp"].iloc[0]),
                        "last_seen": str(window["timestamp"].iloc[-1]),
                    },
                ))
        return alerts

    def is_blacklisted(self, ip: str) -> bool:
        """Return True if ``ip`` falls inside any blacklist entry (cached)."""
        cached = self._blacklist_cache.get(ip)
        if cached is None:
            try:
                addr = ipaddress.ip_address(ip)
                cached = any(addr in net for net in self._blacklist)
            except ValueError:
                cached = False
            self._blacklist_cache[ip] = cached
        return cached

    def detect_blacklisted(self, df: pd.DataFrame) -> List[Alert]:
        """Flag traffic involving blacklisted hosts, aggregated per src->dst pair.

        * Outbound traffic *to* a blacklisted host suggests a compromised
          internal machine (e.g. C2 beaconing) -> HIGH.
        * Inbound traffic *from* a blacklisted host -> MEDIUM.

        V2: hosts found only in threat-intel feeds (see :meth:`add_threat_intel`)
        produce ``THREAT_INTEL_HIT`` alerts with the same severity logic.
        """
        if not self._blacklist and not self.threat_intel_size:
            return []
        unique_ips = pd.unique(pd.concat([df["src_ip"], df["dst_ip"]]))
        bad_ips = {ip for ip in unique_ips
                   if self.is_blacklisted(str(ip)) or self.intel_source(str(ip)) is not None}
        if not bad_ips:
            return []

        src_bad = df["src_ip"].isin(bad_ips)
        dst_bad = df["dst_ip"].isin(bad_ips)
        mask = src_bad | dst_bad
        hits = df[mask].copy()
        # A row is "outbound" when the destination is the blacklisted end.
        hits["outbound"] = dst_bad[mask]
        hits["bad_ip"] = np.where(hits["outbound"], hits["dst_ip"], hits["src_ip"])
        hits["peer_ip"] = np.where(hits["outbound"], hits["src_ip"], hits["dst_ip"])

        # One alert per (blacklisted host, direction) to avoid alert floods.
        alerts: List[Alert] = []
        for (bad_ip, outbound), group in hits.groupby(["bad_ip", "outbound"], sort=False):
            outbound = bool(outbound)
            peers = sorted(str(p) for p in group["peer_ip"].unique())
            peer_label = peers[0] if len(peers) == 1 else f"{len(peers)} hosts"
            src, dst = (peer_label, bad_ip) if outbound else (bad_ip, peer_label)
            direction = "Outbound connections to" if outbound else "Inbound traffic from"
            ports = sorted(int(p) for p in group["dst_port"].unique())
            details = {
                "blacklisted_ip": str(bad_ip),
                "direction": "outbound" if outbound else "inbound",
                "events": int(len(group)),
                "peers": peers[:20],
                "total_bytes": int(group["packet_length"].sum()),
                "dst_ports": ports,
                "first_seen": str(group["timestamp"].iloc[0]),
                "last_seen": str(group["timestamp"].iloc[-1]),
            }
            if self.is_blacklisted(str(bad_ip)):
                alert_type = AlertType.BLACKLISTED_IP
                description = (f"{direction} blacklisted host {bad_ip}: {len(group)} events, "
                               f"{len(peers)} internal peer(s), dst ports {ports[:5]}")
            else:
                feed = self.intel_source(str(bad_ip)) or "threat feed"
                alert_type = AlertType.THREAT_INTEL_HIT
                description = (f"{direction} host {bad_ip} listed in threat feed '{feed}': "
                               f"{len(group)} events, {len(peers)} internal peer(s), "
                               f"dst ports {ports[:5]}")
                details["threat_feed"] = feed
            alerts.append(Alert(
                timestamp=group["timestamp"].iloc[0].to_pydatetime(),
                alert_type=alert_type,
                severity=Severity.HIGH if outbound else Severity.MEDIUM,
                source_ip=str(src),
                dest_ip=str(dst),
                description=description,
                details=details,
            ))
        return alerts


# --------------------------------------------------------------------------- #
# Machine-learning detection
# --------------------------------------------------------------------------- #
def _rolling_count_and_sum(times_ns: np.ndarray, values: np.ndarray,
                           window_ns: int) -> Tuple[np.ndarray, np.ndarray]:
    """Trailing-window event count and value sum for sorted timestamps.

    For each event *i* the window covers events with
    ``times[i] - window_ns <= t <= times[i]``. Uses ``searchsorted`` and a
    cumulative sum, so it runs in O(n log n).
    """
    idx = np.arange(len(times_ns))
    left = np.searchsorted(times_ns, times_ns - window_ns, side="left")
    counts = idx - left + 1
    csum = np.concatenate(([0], np.cumsum(values, dtype=np.int64)))
    sums = csum[idx + 1] - csum[left]
    return counts, sums


class MLAnomalyDetector:
    """Isolation Forest detector for traffic-volume and packet-size anomalies.

    Features (see ``config.MLConfig.feature_columns``):

    * ``packet_length`` - size of the record in bytes.
    * ``src_conn_freq`` - records sent by the same source in the trailing window.
    * ``src_bytes_window`` - bytes sent by the same source in the trailing window.
    * ``pair_conn_freq`` - records for the same src->dst pair in the trailing window.

    Args:
        config: Application configuration (``config.ml`` is used).
    """

    def __init__(self, config: AppConfig = CONFIG) -> None:
        self.ml: MLConfig = config.ml
        self.feature_columns: List[str] = list(self.ml.feature_columns)
        self.model: Optional[IsolationForest] = None
        # Robust baseline statistics captured at fit time (used to explain alerts).
        self._baseline_median: Optional[pd.Series] = None
        self._baseline_spread: Optional[pd.Series] = None

    @property
    def is_fitted(self) -> bool:
        """True once :meth:`fit` has completed."""
        return self.model is not None

    # ------------------------------------------------------------------ #
    def build_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Engineer model features. The returned frame shares ``df``'s index."""
        window_ns = int(self.ml.frequency_window_seconds * _NS_PER_SECOND)
        feats = pd.DataFrame(index=df.index)
        feats["packet_length"] = df["packet_length"].astype(np.int64)

        times = df["timestamp"].to_numpy(dtype="datetime64[ns]").astype(np.int64)
        lengths = feats["packet_length"].to_numpy()
        src_freq = np.zeros(len(df), dtype=np.int64)
        src_bytes = np.zeros(len(df), dtype=np.int64)
        pair_freq = np.zeros(len(df), dtype=np.int64)

        # Positional indices per group; sort each group by time before rolling.
        for positions in df.groupby("src_ip", sort=False, observed=True).indices.values():
            pos = positions[np.argsort(times[positions], kind="mergesort")]
            src_freq[pos], src_bytes[pos] = _rolling_count_and_sum(times[pos], lengths[pos], window_ns)
        for positions in df.groupby(["src_ip", "dst_ip"], sort=False, observed=True).indices.values():
            pos = positions[np.argsort(times[positions], kind="mergesort")]
            pair_freq[pos], _ = _rolling_count_and_sum(times[pos], lengths[pos], window_ns)

        feats["src_conn_freq"] = src_freq
        feats["src_bytes_window"] = src_bytes
        feats["pair_conn_freq"] = pair_freq
        return feats[self.feature_columns]

    def fit(self, df: pd.DataFrame) -> "MLAnomalyDetector":
        """Train the Isolation Forest on ``df`` (assumed mostly normal traffic).

        Raises:
            ValueError: If fewer than ``min_training_samples`` rows are supplied.
        """
        if len(df) < self.ml.min_training_samples:
            raise ValueError(f"Need at least {self.ml.min_training_samples} records to train, "
                             f"got {len(df)}")
        features = self.build_features(df)
        self.model = IsolationForest(
            n_estimators=self.ml.n_estimators,
            contamination=self.ml.contamination,
            max_samples=self.ml.max_samples,
            random_state=self.ml.random_state,
            n_jobs=-1,
        )
        self.model.fit(features.to_numpy(dtype=float))
        self._baseline_median = features.median()
        iqr = features.quantile(0.75) - features.quantile(0.25)
        self._baseline_spread = iqr.clip(lower=1.0)  # avoid divide-by-zero on flat features
        return self

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """Score ``df`` with the trained model.

        Returns:
            Features plus ``anomaly_score`` (lower = more anomalous; < 0 means
            outside the learned boundary) and boolean ``is_anomaly``.

        Raises:
            RuntimeError: If called before :meth:`fit`.
        """
        if self.model is None:
            raise RuntimeError("MLAnomalyDetector.predict() called before fit()")
        features = self.build_features(df)
        matrix = features.to_numpy(dtype=float)
        scored = features.copy()
        scored["anomaly_score"] = self.model.decision_function(matrix)
        scored["is_anomaly"] = self.model.predict(matrix) == -1
        return scored

    def severity_for_score(self, score: float) -> Severity:
        """Map an Isolation Forest decision score to a severity level."""
        if score <= self.ml.high_severity_score:
            return Severity.HIGH
        if score <= self.ml.medium_severity_score:
            return Severity.MEDIUM
        return Severity.LOW

    def _explain(self, row: pd.Series) -> Tuple[str, float]:
        """Return the feature deviating most from baseline and its robust z-score."""
        assert self._baseline_median is not None and self._baseline_spread is not None
        z = (row[self.feature_columns] - self._baseline_median) / self._baseline_spread
        feature = str(z.abs().idxmax())
        return feature, float(z[feature])

    def detect(self, df: pd.DataFrame, refit: bool = True) -> Tuple[List[Alert], pd.DataFrame]:
        """Fit (optionally) and score ``df``, aggregating anomalies into alerts.

        Anomalous records are grouped per ``src_ip -> dst_ip`` pair; severity is
        driven by the worst (lowest) anomaly score in the group.

        Returns:
            ``(alerts, scored_frame)``.
        """
        if refit or not self.is_fitted:
            self.fit(df)
        scored = self.predict(df)
        mask = scored["is_anomaly"]
        # Join engineered features onto the raw records (avoid duplicate columns).
        extra = scored.loc[mask, [c for c in scored.columns if c not in df.columns]]
        anomalies = df.loc[mask].join(extra)

        alerts: List[Alert] = []
        for (src, dst), group in anomalies.groupby(["src_ip", "dst_ip"], sort=False, observed=True):
            worst = group.loc[group["anomaly_score"].idxmin()]
            feature, z = self._explain(worst)
            baseline = float(self._baseline_median[feature])  # type: ignore[index]
            alerts.append(Alert(
                timestamp=group["timestamp"].min().to_pydatetime(),
                alert_type=AlertType.ML_ANOMALY,
                severity=self.severity_for_score(float(worst["anomaly_score"])),
                source_ip=str(src),
                dest_ip=str(dst),
                description=(f"Traffic deviates from baseline: {feature}={int(worst[feature]):,} "
                             f"(baseline median {baseline:,.0f}); {len(group)} anomalous record(s)"),
                details={
                    "anomalous_records": int(len(group)),
                    "min_anomaly_score": round(float(worst["anomaly_score"]), 4),
                    "top_feature": feature,
                    "top_feature_value": int(worst[feature]),
                    "top_feature_robust_z": round(z, 2),
                    "max_packet_length": int(group["packet_length"].max()),
                    "max_src_conn_freq": int(group["src_conn_freq"].max()),
                    "dst_ports": sorted(int(p) for p in group["dst_port"].unique())[:10],
                    "first_seen": str(group["timestamp"].min()),
                    "last_seen": str(group["timestamp"].max()),
                },
            ))
        return alerts, scored


# --------------------------------------------------------------------------- #
# V2: DNS tunneling detection
# --------------------------------------------------------------------------- #
def _peer_label(values: pd.Series) -> Tuple[str, List[str]]:
    """Return ``(label, sorted unique values)``; label is the single value or "N hosts"."""
    peers = sorted(str(v) for v in values.unique())
    return (peers[0] if len(peers) == 1 else f"{len(peers)} hosts"), peers


class DNSTunnelingDetector:
    """Flag sources sending an abnormal number of DNS queries in a short window.

    A source triggers when it sends MORE than ``query_threshold`` queries to
    port 53 within ``window_seconds`` (MEDIUM); a peak above
    ``high_severity_queries`` escalates to HIGH.

    Args:
        config: Application configuration (``config.dns`` is used).
    """

    def __init__(self, config: AppConfig = CONFIG) -> None:
        self.dns: DNSConfig = config.dns

    def detect(self, df: pd.DataFrame) -> List[Alert]:
        """Return one alert per incident (merged violating windows) per source."""
        c = self.dns
        if df.empty:
            return []
        data = df[df["dst_port"].isin(c.dns_ports)]
        sizes = data.groupby("src_ip", observed=True).size()
        suspects = sizes[sizes > c.query_threshold].index
        if suspects.empty:
            return []
        data = data[data["src_ip"].isin(suspects)]

        alerts: List[Alert] = []
        for src, group in data.groupby("src_ip", sort=False, observed=True):
            group = group.sort_values("timestamp", kind="mergesort")
            times = group["timestamp"].to_numpy(dtype="datetime64[ns]").astype(np.int64)
            for inc in sliding_window_incidents(times, times, c.window_seconds,
                                                c.query_threshold, count_unique=False):
                window = group.iloc[inc.start_idx: inc.end_idx + 1]
                duration = (window["timestamp"].iloc[-1] - window["timestamp"].iloc[0]).total_seconds()
                dst_label, resolvers = _peer_label(window["dst_ip"])
                severity = Severity.HIGH if inc.peak > c.high_severity_queries else Severity.MEDIUM
                alerts.append(Alert(
                    timestamp=window["timestamp"].iloc[0].to_pydatetime(),
                    alert_type=AlertType.DNS_TUNNELING,
                    severity=severity,
                    source_ip=str(src),
                    dest_ip=dst_label,
                    description=(f"Possible DNS tunneling: {len(window)} DNS queries in "
                                 f"{duration:.1f}s (peak {inc.peak} in {c.window_seconds:g}s, "
                                 f"threshold >{c.query_threshold})"),
                    details={
                        "queries": int(len(window)),
                        "peak_queries_in_window": int(inc.peak),
                        "duration_seconds": round(duration, 3),
                        "resolvers": resolvers[:20],
                        "avg_query_bytes": round(float(window["packet_length"].mean()), 1),
                        "total_bytes": int(window["packet_length"].sum()),
                        "first_seen": str(window["timestamp"].iloc[0]),
                        "last_seen": str(window["timestamp"].iloc[-1]),
                    },
                ))
        return alerts


# --------------------------------------------------------------------------- #
# V2: Beaconing detection
# --------------------------------------------------------------------------- #
class BeaconingDetector:
    """Flag src->dst pairs that connect at a suspiciously regular interval.

    For every pair with more than ``min_connections`` connections the
    inter-arrival times are computed (gaps shorter than ``session_gap_seconds``
    are collapsed so a multi-packet session counts once). The pair is flagged
    when the standard deviation of the intervals is below
    ``max_interval_std_seconds`` and the mean interval is at least
    ``min_mean_interval_seconds`` (which excludes floods and scans).

    Args:
        config: Application configuration (``config.beaconing`` is used).
    """

    def __init__(self, config: AppConfig = CONFIG) -> None:
        self.cfg: BeaconingConfig = config.beaconing

    def _connection_times(self, times_ns: np.ndarray) -> np.ndarray:
        """Collapse events closer than ``session_gap_seconds`` into one connection."""
        if len(times_ns) < 2:
            return times_ns
        gap_ns = self.cfg.session_gap_seconds * _NS_PER_SECOND
        keep = np.concatenate(([True], np.diff(times_ns) >= gap_ns))
        return times_ns[keep]

    def analyse_pair(self, times_ns: np.ndarray) -> Optional[Dict[str, float]]:
        """Return interval statistics if ``times_ns`` (sorted) looks like a beacon."""
        c = self.cfg
        conn = self._connection_times(times_ns)
        if len(conn) <= c.min_connections:
            return None
        intervals = np.diff(conn) / _NS_PER_SECOND
        mean, std = float(intervals.mean()), float(intervals.std())
        if mean < c.min_mean_interval_seconds or std >= c.max_interval_std_seconds:
            return None
        return {"connections": int(len(conn)), "mean_interval": mean, "std_interval": std,
                "min_interval": float(intervals.min()), "max_interval": float(intervals.max())}

    def detect(self, df: pd.DataFrame) -> List[Alert]:
        """Return one alert per beaconing src->dst pair."""
        c = self.cfg
        if df.empty:
            return []
        sizes = df.groupby(["src_ip", "dst_ip"], observed=True).size()
        suspects = sizes[sizes > c.min_connections].index
        if suspects.empty:
            return []
        candidate = df.set_index(["src_ip", "dst_ip"]).loc[suspects].reset_index()

        alerts: List[Alert] = []
        for (src, dst), group in candidate.groupby(["src_ip", "dst_ip"], sort=False, observed=True):
            group = group.sort_values("timestamp", kind="mergesort")
            times = group["timestamp"].to_numpy(dtype="datetime64[ns]").astype(np.int64)
            stats = self.analyse_pair(times)
            if stats is None:
                continue
            high = (stats["std_interval"] < c.high_severity_std_seconds
                    and stats["connections"] >= c.high_severity_min_connections)
            ports = sorted(int(p) for p in group["dst_port"].unique())
            alerts.append(Alert(
                timestamp=group["timestamp"].iloc[0].to_pydatetime(),
                alert_type=AlertType.BEACONING,
                severity=Severity.HIGH if high else Severity.MEDIUM,
                source_ip=str(src),
                dest_ip=str(dst),
                description=(f"Possible C2 beaconing: {stats['connections']} connections every "
                             f"{stats['mean_interval']:.1f}s (std {stats['std_interval']:.2f}s, "
                             f"threshold <{c.max_interval_std_seconds:g}s), dst ports {ports[:5]}"),
                details={
                    "connections": stats["connections"],
                    "mean_interval_seconds": round(stats["mean_interval"], 3),
                    "std_interval_seconds": round(stats["std_interval"], 3),
                    "min_interval_seconds": round(stats["min_interval"], 3),
                    "max_interval_seconds": round(stats["max_interval"], 3),
                    "dst_ports": ports[:10],
                    "first_seen": str(group["timestamp"].iloc[0]),
                    "last_seen": str(group["timestamp"].iloc[-1]),
                },
            ))
        return alerts


# --------------------------------------------------------------------------- #
# V2: Time-of-day anomaly detection
# --------------------------------------------------------------------------- #
class TimeOfDayDetector:
    """Flag sources with heavy activity outside business hours.

    Off-hours are every hour not in ``[business_hours_start, business_hours_end)``
    (default 22:00-06:00; windows that wrap past midnight are supported). A
    source with MORE than ``connection_threshold`` off-hours connections is
    MEDIUM; more than ``high_severity_connections`` is HIGH.

    Args:
        config: Application configuration (``config.time_of_day`` is used).
    """

    def __init__(self, config: AppConfig = CONFIG) -> None:
        self.cfg: TimeOfDayConfig = config.time_of_day

    def off_hours_mask(self, timestamps: pd.Series) -> pd.Series:
        """Boolean mask: True where the timestamp falls outside business hours."""
        start, end = self.cfg.business_hours_start, self.cfg.business_hours_end
        hours = timestamps.dt.hour
        if start <= end:
            business = (hours >= start) & (hours < end)
        else:  # business window wraps midnight, e.g. 20:00-04:00 night shift
            business = (hours >= start) | (hours < end)
        return ~business

    @property
    def off_hours_label(self) -> str:
        """Human-readable off-hours range, e.g. ``"22:00-06:00"``."""
        return f"{self.cfg.business_hours_end % 24:02d}:00-{self.cfg.business_hours_start:02d}:00"

    def detect(self, df: pd.DataFrame) -> List[Alert]:
        """Return one alert per source exceeding the off-hours threshold."""
        c = self.cfg
        if df.empty:
            return []
        off = df[self.off_hours_mask(df["timestamp"])]
        if off.empty:
            return []
        sizes = off.groupby("src_ip", observed=True).size()
        suspects = sizes[sizes > c.connection_threshold].index
        alerts: List[Alert] = []
        for src in suspects:
            group = off[off["src_ip"] == src].sort_values("timestamp", kind="mergesort")
            count = int(len(group))
            dst_label, dsts = _peer_label(group["dst_ip"])
            ports = group["dst_port"].value_counts().head(5)
            alerts.append(Alert(
                timestamp=group["timestamp"].iloc[0].to_pydatetime(),
                alert_type=AlertType.TIME_OF_DAY_ANOMALY,
                severity=Severity.HIGH if count > c.high_severity_connections else Severity.MEDIUM,
                source_ip=str(src),
                dest_ip=dst_label,
                description=(f"Off-hours activity: {count} connections during {self.off_hours_label} "
                             f"to {len(dsts)} destination(s) (threshold >{c.connection_threshold})"),
                details={
                    "off_hours_connections": count,
                    "off_hours_window": self.off_hours_label,
                    "destinations": dsts[:20],
                    "top_dst_ports": {str(int(p)): int(n) for p, n in ports.items()},
                    "total_bytes": int(group["packet_length"].sum()),
                    "first_seen": str(group["timestamp"].iloc[0]),
                    "last_seen": str(group["timestamp"].iloc[-1]),
                },
            ))
        return alerts


# --------------------------------------------------------------------------- #
# Combined engine
# --------------------------------------------------------------------------- #
@dataclass
class DetectionResult:
    """Output of :meth:`DetectionEngine.run`."""

    alerts: List[Alert] = field(default_factory=list)
    rule_alerts: List[Alert] = field(default_factory=list)
    ml_alerts: List[Alert] = field(default_factory=list)
    ml_scores: Optional[pd.DataFrame] = None
    timings: Dict[str, float] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)


class DetectionEngine:
    """Runs rule-based and ML detection, then merges the results.

    Merging strategy: rule and ML alerts are kept side by side (they describe
    different evidence), but any ML alert whose source IP was also flagged by
    a rule is annotated with ``details["corroborated_by"]`` and the
    description is suffixed accordingly, which helps analysts prioritise.

    V2 detectors (DNS tunneling, beaconing, time-of-day) run after the V1
    rules; their alerts are added to ``rule_alerts``. Each one is isolated in
    a try/except so a failure is reported as a warning and never stops the
    V1 pipeline.

    Args:
        config: Application configuration.
        enable_ml: Set False to run only the rule-based detectors.
        enable_dns: Run :class:`DNSTunnelingDetector`.
        enable_beaconing: Run :class:`BeaconingDetector`.
        enable_time_of_day: Run :class:`TimeOfDayDetector`.
        threat_intel: Optional ``{ip_or_cidr: feed_name}`` entries merged into
            the blacklist (see :mod:`threat_intel`).
    """

    def __init__(self, config: AppConfig = CONFIG, enable_ml: bool = True, *,
                 enable_dns: bool = True, enable_beaconing: bool = True,
                 enable_time_of_day: bool = True,
                 threat_intel: Optional[Mapping[str, str]] = None) -> None:
        self.config = config
        self.rule_detector = RuleBasedDetector(config, extra_blacklist=threat_intel)
        self.ml_detector: Optional[MLAnomalyDetector] = MLAnomalyDetector(config) if enable_ml else None
        self.v2_detectors: List[Tuple[str, object]] = []
        if enable_dns:
            self.v2_detectors.append(("dns", DNSTunnelingDetector(config)))
        if enable_beaconing:
            self.v2_detectors.append(("beaconing", BeaconingDetector(config)))
        if enable_time_of_day:
            self.v2_detectors.append(("time_of_day", TimeOfDayDetector(config)))

    def run_v2_detectors(self, df: pd.DataFrame, result: Optional[DetectionResult] = None,
                         names: Optional[Sequence[str]] = None) -> List[Alert]:
        """Run the enabled V2 detectors on ``df`` (each failure becomes a warning).

        Args:
            df: Records to analyse (sorted by timestamp).
            result: Optional result object receiving timings and warnings.
            names: Restrict to these detector names (``dns``, ``beaconing``,
                ``time_of_day``); default all enabled.
        """
        alerts: List[Alert] = []
        for name, detector in self.v2_detectors:
            if names is not None and name not in names:
                continue
            start = time.perf_counter()
            try:
                alerts.extend(detector.detect(df))  # type: ignore[attr-defined]
            except Exception as exc:  # noqa: BLE001 - never break the V1 pipeline
                if result is not None:
                    result.warnings.append(f"{name} detection skipped: {exc}")
            if result is not None:
                result.timings[name] = time.perf_counter() - start
        return alerts

    def run(self, df: pd.DataFrame) -> DetectionResult:
        """Analyse ``df`` and return a merged, chronologically sorted result."""
        result = DetectionResult()
        if df.empty:
            result.warnings.append("No records to analyse.")
            return result

        start = time.perf_counter()
        result.rule_alerts = self.rule_detector.detect(df)
        result.timings["rules"] = time.perf_counter() - start

        if self.v2_detectors:
            ordered = df.sort_values("timestamp", kind="mergesort")
            result.rule_alerts = result.rule_alerts + self.run_v2_detectors(ordered, result)

        if self.ml_detector is not None:
            start = time.perf_counter()
            try:
                result.ml_alerts, result.ml_scores = self.ml_detector.detect(df)
            except ValueError as exc:  # e.g. not enough samples
                result.warnings.append(f"ML detection skipped: {exc}")
            result.timings["ml"] = time.perf_counter() - start

        result.ml_alerts = self._corroborate(result.ml_alerts, result.rule_alerts)
        result.alerts = sorted(result.rule_alerts + result.ml_alerts,
                               key=lambda a: (a.timestamp, -a.severity.rank))
        return result

    @staticmethod
    def _corroborate(ml_alerts: Sequence[Alert], rule_alerts: Sequence[Alert]) -> List[Alert]:
        """Annotate ML alerts whose source was also caught by a rule."""
        rule_types: Dict[str, set] = {}
        for alert in rule_alerts:
            rule_types.setdefault(alert.source_ip, set()).add(alert.alert_type.value)

        merged: List[Alert] = []
        for alert in ml_alerts:
            types = rule_types.get(alert.source_ip)
            if types:
                details = {**alert.details, "corroborated_by": sorted(types)}
                alert = replace(alert, details=details,
                                description=f"{alert.description} [corroborates {', '.join(sorted(types))}]")
            merged.append(alert)
        return merged
