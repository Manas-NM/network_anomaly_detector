"""
mock_data_generator.py - Synthetic network log generator with embedded anomalies.

Each generated CSV row represents one connection / flow record with the
columns defined in :class:`config.SchemaConfig`::

    Timestamp, Source IP, Destination IP, Source Port, Destination Port,
    Protocol, Packet Length

The data set mixes realistic *background* traffic with several deliberately
injected attack scenarios so that every detector has something to find:

=====================  ======================================================
Scenario               Description
=====================  ======================================================
Normal traffic         Random clients/servers, common ports (80/443/22/53/8080),
                       TCP/UDP/ICMP, packet sizes 64-1500 bytes.
Port scan (fast)       One attacker probing 60+ unique ports on one host in ~3 s.
Port scan (small)      A quieter scan of ~14 ports in ~4 s (MEDIUM severity).
SSH brute force        60 connections to port 22 on one host in ~15 s.
RDP brute force        25 connections to port 3389 in ~8 s (MEDIUM severity).
Blacklisted traffic    Inbound traffic from, and outbound beaconing to,
                       known-bad IPs listed in ``config.RuleConfig``.
Jumbo packets          Packets with abnormal sizes (> 9000 bytes).
Exfiltration burst     An internal host pushing many large packets to an
                       external server in a short burst (ML-only finding).
Malformed rows         A handful of broken lines to exercise the parser.
=====================  ======================================================

Usage::

    python mock_data_generator.py                      # defaults from config
    python mock_data_generator.py --rows 20000 --seed 7 --output data/big.csv
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from config import CONFIG, AppConfig

# A single generated record (internal column name -> value).
Record = Dict[str, object]

# --------------------------------------------------------------------------- #
# Scenario constants (kept here, not in config, because they describe the
# *synthetic world* rather than detector behaviour).
# --------------------------------------------------------------------------- #
PORT_SCAN_ATTACKER = "203.0.113.45"
PORT_SCAN_TARGET = "192.168.1.10"
SMALL_SCAN_ATTACKER = "203.0.113.77"
SMALL_SCAN_TARGET = "192.168.1.12"
SSH_BRUTE_ATTACKER = "198.51.100.23"
SSH_BRUTE_TARGET = "192.168.1.20"
RDP_BRUTE_ATTACKER = "198.51.100.61"
RDP_BRUTE_TARGET = "192.168.1.25"
EXFIL_SOURCE = "10.0.0.37"
EXFIL_DESTINATION = "93.184.216.200"

#: Weighted service catalogue for normal traffic: (dst_port, protocol, weight).
NORMAL_SERVICES: Sequence[tuple] = (
    (443, "TCP", 0.42),
    (80, "TCP", 0.20),
    (53, "UDP", 0.18),
    (22, "TCP", 0.06),
    (8080, "TCP", 0.09),
    (0, "ICMP", 0.05),
)


@dataclass
class GenerationSummary:
    """Statistics describing what was written to disk."""

    output_path: Path
    total_rows: int
    normal_rows: int
    anomaly_rows: Dict[str, int]
    malformed_rows: int


class MockDataGenerator:
    """Generates synthetic network logs with embedded, labelled anomalies.

    Args:
        config: Application configuration (defaults to the shared ``CONFIG``).
        seed: Random seed overriding ``config.generator.random_seed``.
    """

    def __init__(self, config: AppConfig = CONFIG, seed: Optional[int] = None) -> None:
        self.config = config
        self.rng = random.Random(config.generator.random_seed if seed is None else seed)
        self.start_time = datetime.fromisoformat(config.generator.start_time)
        self.duration = config.generator.duration_seconds

        # Host pools: internal clients, internal servers and the wider internet.
        self.internal_clients: List[str] = [f"10.0.0.{i}" for i in range(2, 62)]
        self.internal_servers: List[str] = [f"192.168.1.{i}" for i in range(2, 30)]
        self.external_hosts: List[str] = self._random_public_ips(150)

        # Expand blacklist entries (single IPs or CIDRs) into concrete hosts.
        self.blacklisted_hosts: List[str] = self._expand_blacklist(config.rules.blacklisted_ips)

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _random_public_ips(self, count: int) -> List[str]:
        """Return ``count`` unique, globally routable, non-documentation IPv4s."""
        hosts: set = set()
        while len(hosts) < count:
            candidate = ipaddress.IPv4Address(self.rng.randint(0x01000000, 0xDFFFFFFF))
            if candidate.is_global and not candidate.is_multicast:
                hosts.add(str(candidate))
        return sorted(hosts)

    def _expand_blacklist(self, entries: Sequence[str]) -> List[str]:
        """Turn blacklist entries into a list of concrete host addresses."""
        hosts: List[str] = []
        for entry in entries:
            network = ipaddress.ip_network(entry, strict=False)
            # Use at most a few hosts per CIDR to keep traffic focused.
            members = [str(h) for h in network.hosts()] or [str(network.network_address)]
            hosts.extend(members[:3])
        return hosts

    def _ts(self, offset_seconds: float) -> datetime:
        """Convert a second offset into an absolute timestamp."""
        return self.start_time + timedelta(seconds=offset_seconds)

    def _ephemeral_port(self) -> int:
        """Random client-side (ephemeral) port."""
        return self.rng.randint(49152, 65535)

    def _normal_packet_length(self, protocol: str) -> int:
        """Realistic packet size: bimodal TCP, small UDP/ICMP (64-1500 bytes)."""
        if protocol == "ICMP":
            return self.rng.choice([64, 84, 98, 128])
        if protocol == "UDP":
            return self.rng.randint(64, 512)
        # TCP: mix of small control packets and near-MTU data packets.
        roll = self.rng.random()
        if roll < 0.35:
            return self.rng.randint(64, 128)
        if roll < 0.75:
            return self.rng.randint(1200, 1500)
        return self.rng.randint(129, 1199)

    @staticmethod
    def _record(ts: datetime, src: str, dst: str, sport: int, dport: int,
                proto: str, length: int) -> Record:
        """Build a record dict using internal column names."""
        return {
            "timestamp": ts,
            "src_ip": src,
            "dst_ip": dst,
            "src_port": sport,
            "dst_port": dport,
            "protocol": proto,
            "packet_length": length,
        }

    # ------------------------------------------------------------------ #
    # Traffic scenarios
    # ------------------------------------------------------------------ #
    def generate_normal_traffic(self, count: int) -> List[Record]:
        """Background traffic between internal clients, servers and the internet."""
        ports = [s[0] for s in NORMAL_SERVICES]
        weights = [s[2] for s in NORMAL_SERVICES]
        protocols = {s[0]: s[1] for s in NORMAL_SERVICES}
        records: List[Record] = []
        for _ in range(count):
            dport = self.rng.choices(ports, weights=weights, k=1)[0]
            proto = protocols[dport]
            # 70% outbound (client -> internet/server), 30% inbound from internet.
            if self.rng.random() < 0.7:
                src = self.rng.choice(self.internal_clients)
                dst = self.rng.choice(self.external_hosts + self.internal_servers)
            else:
                src = self.rng.choice(self.external_hosts)
                dst = self.rng.choice(self.internal_servers)
            sport = 0 if proto == "ICMP" else self._ephemeral_port()
            ts = self._ts(self.rng.uniform(0, self.duration))
            records.append(self._record(ts, src, dst, sport, dport, proto,
                                        self._normal_packet_length(proto)))
        return records

    def generate_port_scan(self, attacker: str, target: str, num_ports: int,
                           start: float, span: float) -> List[Record]:
        """SYN-style scan: ``num_ports`` unique ports probed within ``span`` seconds."""
        ports = self.rng.sample(range(1, 1025), num_ports)
        sport = self._ephemeral_port()  # scanners often reuse one source port
        return [
            self._record(self._ts(start + span * i / num_ports), attacker, target,
                         sport, port, "TCP", self.rng.randint(40, 64))
            for i, port in enumerate(ports)
        ]

    def generate_brute_force(self, attacker: str, target: str, port: int,
                             attempts: int, start: float, span: float) -> List[Record]:
        """Repeated short connections to an authentication service."""
        records: List[Record] = []
        for i in range(attempts):
            jitter = self.rng.uniform(-0.05, 0.05)
            ts = self._ts(start + span * i / attempts + jitter)
            records.append(self._record(ts, attacker, target, self._ephemeral_port(),
                                        port, "TCP", self.rng.randint(60, 180)))
        return records

    def generate_blacklisted_traffic(self, inbound: int, outbound: int) -> List[Record]:
        """Traffic from blacklisted hosts (inbound) and beaconing to them (outbound)."""
        records: List[Record] = []
        for _ in range(inbound):
            src = self.rng.choice(self.blacklisted_hosts)
            dst = self.rng.choice(self.internal_servers)
            dport = self.rng.choice([80, 443, 22, 8080])
            records.append(self._record(self._ts(self.rng.uniform(0, self.duration)), src, dst,
                                        self._ephemeral_port(), dport, "TCP",
                                        self._normal_packet_length("TCP")))
        # A compromised client "phoning home" to a C2 server periodically.
        beacon_src = self.rng.choice(self.internal_clients)
        c2_server = self.blacklisted_hosts[1]
        interval = self.duration / max(outbound, 1)
        for i in range(outbound):
            ts = self._ts(i * interval + self.rng.uniform(0, 5))
            records.append(self._record(ts, beacon_src, c2_server, self._ephemeral_port(),
                                        4444, "TCP", self.rng.randint(200, 400)))
        return records

    def generate_jumbo_packets(self, count: int) -> List[Record]:
        """Abnormally large packets (> 9000 bytes) from ordinary hosts."""
        records: List[Record] = []
        for _ in range(count):
            src = self.rng.choice(self.internal_clients + self.external_hosts)
            dst = self.rng.choice(self.internal_servers + self.external_hosts)
            proto = self.rng.choice(["TCP", "UDP"])
            dport = self.rng.choice([443, 80, 53, 8080])
            records.append(self._record(self._ts(self.rng.uniform(0, self.duration)), src, dst,
                                        self._ephemeral_port(), dport, proto,
                                        self.rng.randint(9001, 16000)))
        return records

    def generate_exfiltration_burst(self, count: int, start: float, span: float) -> List[Record]:
        """Large outbound transfer burst over HTTPS (volume anomaly)."""
        return [
            self._record(self._ts(start + span * i / count), EXFIL_SOURCE, EXFIL_DESTINATION,
                         self._ephemeral_port(), 443, "TCP", self.rng.randint(1400, 1500))
            for i in range(count)
        ]

    def malformed_lines(self, count: int) -> List[List[str]]:
        """Broken CSV rows: bad IPs, bad ports, unknown protocols, missing fields."""
        templates = [
            ["not-a-timestamp", "10.0.0.5", "192.168.1.3", "50000", "443", "TCP", "512"],
            ["2026-10-05 08:15:00.000000", "999.10.0.1", "192.168.1.3", "50000", "443", "TCP", "512"],
            ["2026-10-05 08:16:00.000000", "10.0.0.5", "192.168.1.3", "70000", "443", "TCP", "512"],
            ["2026-10-05 08:17:00.000000", "10.0.0.5", "192.168.1.3", "50000", "443", "SCTP", "512"],
            ["2026-10-05 08:18:00.000000", "10.0.0.5", "192.168.1.3", "50000", "443", "TCP", "-20"],
            ["2026-10-05 08:19:00.000000", "10.0.0.5", "", "50000", "443", "TCP", "abc"],
            ["2026-10-05 08:20:00.000000", "10.0.0.5"],  # truncated line
        ]
        return [templates[i % len(templates)] for i in range(count)]

    # ------------------------------------------------------------------ #
    # Orchestration
    # ------------------------------------------------------------------ #
    def generate(self, total_rows: Optional[int] = None) -> tuple:
        """Generate all records.

        Args:
            total_rows: Approximate total record count (normal + anomalies).

        Returns:
            Tuple ``(records, anomaly_counts)`` where ``records`` is sorted by
            timestamp and ``anomaly_counts`` maps scenario name -> row count.
        """
        total = total_rows or self.config.generator.total_rows
        d = self.duration
        anomalies: Dict[str, List[Record]] = {
            "port_scan_fast": self.generate_port_scan(
                PORT_SCAN_ATTACKER, PORT_SCAN_TARGET, 64, start=d * 0.20, span=3.0),
            "port_scan_small": self.generate_port_scan(
                SMALL_SCAN_ATTACKER, SMALL_SCAN_TARGET, 14, start=d * 0.65, span=4.0),
            "ssh_brute_force": self.generate_brute_force(
                SSH_BRUTE_ATTACKER, SSH_BRUTE_TARGET, 22, 60, start=d * 0.40, span=15.0),
            "rdp_brute_force": self.generate_brute_force(
                RDP_BRUTE_ATTACKER, RDP_BRUTE_TARGET, 3389, 25, start=d * 0.80, span=8.0),
            "blacklisted_ip": self.generate_blacklisted_traffic(inbound=30, outbound=20),
            "jumbo_packets": self.generate_jumbo_packets(25),
            "exfiltration_burst": self.generate_exfiltration_burst(120, start=d * 0.55, span=20.0),
        }
        anomaly_counts = {name: len(rows) for name, rows in anomalies.items()}
        normal_count = max(total - sum(anomaly_counts.values()), 0)

        records = self.generate_normal_traffic(normal_count)
        for rows in anomalies.values():
            records.extend(rows)
        records.sort(key=lambda r: r["timestamp"])
        return records, anomaly_counts

    def write_csv(self, output_path: Optional[Path] = None,
                  total_rows: Optional[int] = None,
                  malformed: Optional[int] = None) -> GenerationSummary:
        """Generate data and write it to a CSV file.

        Args:
            output_path: Destination file (defaults to ``config.paths.log_file``).
            total_rows: Approximate number of valid rows to produce.
            malformed: Number of malformed rows to sprinkle in.

        Returns:
            A :class:`GenerationSummary` describing the written file.
        """
        path = Path(output_path or self.config.paths.log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        malformed_count = self.config.generator.malformed_rows if malformed is None else malformed

        records, anomaly_counts = self.generate(total_rows)
        fmt = self.config.schema.timestamp_format
        columns = self.config.schema.internal_columns
        rows: List[List[str]] = [
            [r["timestamp"].strftime(fmt) if c == "timestamp" else str(r[c]) for c in columns]
            for r in records
        ]
        # Insert malformed rows at random positions.
        for bad in self.malformed_lines(malformed_count):
            rows.insert(self.rng.randint(0, len(rows)), bad)

        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(self.config.schema.csv_headers)
            writer.writerows(rows)

        return GenerationSummary(
            output_path=path,
            total_rows=len(rows),
            normal_rows=len(records) - sum(anomaly_counts.values()),
            anomaly_rows=anomaly_counts,
            malformed_rows=malformed_count,
        )


def generate_mock_data(output_path: Optional[Path] = None, total_rows: Optional[int] = None,
                       seed: Optional[int] = None, malformed: Optional[int] = None,
                       config: AppConfig = CONFIG) -> GenerationSummary:
    """Convenience wrapper used by ``main.py``."""
    return MockDataGenerator(config, seed=seed).write_csv(output_path, total_rows, malformed)


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """CLI argument parsing for standalone use."""
    parser = argparse.ArgumentParser(description="Generate synthetic network logs with anomalies.")
    parser.add_argument("-o", "--output", type=Path, default=CONFIG.paths.log_file,
                        help="Output CSV path (default: %(default)s)")
    parser.add_argument("-n", "--rows", type=int, default=CONFIG.generator.total_rows,
                        help="Approximate number of rows (default: %(default)s)")
    parser.add_argument("-s", "--seed", type=int, default=CONFIG.generator.random_seed,
                        help="Random seed (default: %(default)s)")
    parser.add_argument("-m", "--malformed", type=int, default=CONFIG.generator.malformed_rows,
                        help="Malformed rows to inject (default: %(default)s)")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> None:
    """Entry point for ``python mock_data_generator.py``."""
    args = _parse_args(argv)
    summary = generate_mock_data(args.output, args.rows, args.seed, args.malformed)
    print(f"[+] Wrote {summary.total_rows:,} rows to {summary.output_path}")
    print(f"    {'normal rows':<18}: {summary.normal_rows:,}")
    for name, count in summary.anomaly_rows.items():
        print(f"    {name:<18}: {count}")
    print(f"    {'malformed rows':<18}: {summary.malformed_rows}")


if __name__ == "__main__":
    main()
