"""
pcap_parser.py - Read packet captures (.pcap / .pcapng) into the log schema.

:class:`PcapParser` uses `dpkt <https://dpkt.readthedocs.io>`_ to decode each
captured packet and produces the same :class:`log_parser.ParseResult` /
DataFrame schema as the CSV parser (``timestamp, src_ip, dst_ip, src_port,
dst_port, protocol, packet_length``), so every detector works unchanged.

* Link layers: Ethernet, Linux "cooked" capture (SLL), BSD loopback and raw IP.
* Network layers: IPv4 and IPv6.
* Transport: TCP, UDP and ICMP / ICMPv6 (reported as ``ICMP``, ports = 0).
  Anything else (ARP, IGMP, truncated frames, ...) is skipped and counted in
  ``ParseResult.errors`` instead of raising.
* ``packet_length`` is the IP datagram length (header + payload).

The file format (classic pcap vs pcapng) is detected from the magic bytes, so
the extension does not need to be accurate.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

import pandas as pd

from config import CONFIG, AppConfig, PcapConfig
from log_parser import LogParseError, ParseResult, RowError

logger = logging.getLogger("network_anomaly_detector.pcap")

#: Magic numbers of the supported capture formats.
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
_PCAP_MAGICS = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}

#: Common libpcap link-layer types (DLT_*).
_DLT_NULL, _DLT_EN10MB, _DLT_RAW, _DLT_LINUX_SLL = 0, 1, 101, 113
_DLT_RAW_ALIASES = {12, 14, _DLT_RAW, 228, 229}

#: IP protocol numbers handled by the parser.
_PROTO_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMP"}


def is_pcap_file(path: Path | str, config: AppConfig = CONFIG) -> bool:
    """True if ``path`` has a capture extension or starts with a pcap/pcapng magic number."""
    path = Path(path)
    if path.suffix.lower() in config.pcap.extensions:
        return True
    try:
        with path.open("rb") as fh:
            magic = fh.read(4)
    except OSError:
        return False
    return magic == _PCAPNG_MAGIC or magic in _PCAP_MAGICS


class PcapParser:
    """Converts a packet capture into the detector's DataFrame schema.

    Args:
        config: Application configuration (``config.pcap`` is used).
    """

    def __init__(self, config: AppConfig = CONFIG) -> None:
        self.cfg: PcapConfig = config.pcap
        self.schema = config.schema

    # ------------------------------------------------------------------ #
    @staticmethod
    def _import_dpkt() -> Any:
        """Import dpkt with a helpful error message when it is missing."""
        try:
            import dpkt  # noqa: WPS433 - optional dependency
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise LogParseError("Reading .pcap files requires the 'dpkt' package: "
                                "pip install dpkt") from exc
        return dpkt

    def _open_reader(self, dpkt: Any, fh: Any, path: Path) -> Any:
        """Return a dpkt reader for classic pcap or pcapng based on the magic bytes."""
        magic = fh.read(4)
        fh.seek(0)
        try:
            if magic == _PCAPNG_MAGIC:
                return dpkt.pcapng.Reader(fh)
            if magic in _PCAP_MAGICS:
                return dpkt.pcap.Reader(fh)
        except (ValueError, dpkt.dpkt.UnpackError) as exc:
            raise LogParseError(f"Corrupt capture file header in {path}: {exc}") from exc
        raise LogParseError(f"{path} is not a pcap/pcapng capture (unknown magic {magic.hex()})")

    @staticmethod
    def _network_layer(dpkt: Any, datalink: int, buf: bytes) -> Any:
        """Strip the link layer and return the IP/IPv6 object (or another dpkt object)."""
        if datalink == _DLT_EN10MB:
            return dpkt.ethernet.Ethernet(buf).data
        if datalink == _DLT_LINUX_SLL:
            return dpkt.sll.SLL(buf).data
        if datalink == _DLT_NULL:
            return dpkt.loopback.Loopback(buf).data
        if datalink in _DLT_RAW_ALIASES:
            version = buf[0] >> 4 if buf else 0
            return dpkt.ip6.IP6(buf) if version == 6 else dpkt.ip.IP(buf)
        raise ValueError(f"unsupported link type {datalink}")

    def _decode(self, dpkt: Any, datalink: int, ts: float, buf: bytes
                ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """Decode one packet into a record dict, or return ``(None, skip_reason)``."""
        try:
            ip = self._network_layer(dpkt, datalink, buf)
        except Exception as exc:  # noqa: BLE001 - malformed frame
            return None, f"undecodable frame ({type(exc).__name__})"
        if isinstance(ip, dpkt.ip.IP):
            family, proto, length = socket.AF_INET, ip.p, ip.len
        elif isinstance(ip, dpkt.ip6.IP6):
            family, proto, length = socket.AF_INET6, ip.nxt, ip.plen + 40
        else:
            return None, f"non-IP packet ({type(ip).__name__})"
        name = _PROTO_NAMES.get(proto)
        if name is None:
            return None, f"unsupported IP protocol {proto}"
        transport = ip.data
        sport = dport = 0
        if name in ("TCP", "UDP"):
            if not hasattr(transport, "sport"):
                return None, f"truncated {name} header"
            sport, dport = int(transport.sport), int(transport.dport)
        try:
            src = str(ipaddress.ip_address(socket.inet_ntop(family, ip.src)))
            dst = str(ipaddress.ip_address(socket.inet_ntop(family, ip.dst)))
        except (ValueError, OSError):
            return None, "invalid IP address"
        length = int(length) if length else len(buf)
        return {"timestamp": datetime.fromtimestamp(float(ts)), "src_ip": src, "dst_ip": dst,
                "src_port": sport, "dst_port": dport, "protocol": name,
                "packet_length": max(1, min(length, self.schema.max_packet_length))}, None

    def iter_records(self, path: Path | str) -> Iterator[Tuple[int, Optional[Dict[str, Any]], Optional[str]]]:
        """Yield ``(packet_number, record or None, skip_reason or None)`` for each packet."""
        dpkt = self._import_dpkt()
        path = Path(path)
        if not path.is_file():
            raise LogParseError(f"Capture file not found: {path}")
        with path.open("rb") as fh:
            reader = self._open_reader(dpkt, fh, path)
            datalink = int(reader.datalink())
            number = 0
            try:
                for ts, buf in reader:
                    number += 1
                    record, reason = self._decode(dpkt, datalink, ts, buf)
                    yield number, record, reason
                    if self.cfg.max_packets is not None and number >= self.cfg.max_packets:
                        break
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, ValueError) as exc:
                # A truncated capture (e.g. tcpdump killed mid-write) - keep what we have.
                yield number + 1, None, f"capture truncated: {exc}"

    def parse(self, path: Path | str) -> ParseResult:
        """Read the whole capture and return a :class:`ParseResult`.

        Raises:
            LogParseError: Missing file, unknown format or dpkt not installed.
        """
        path = Path(path)
        records: List[Dict[str, Any]] = []
        errors: List[RowError] = []
        reasons: Counter = Counter()
        total = 0
        for number, record, reason in self.iter_records(path):
            total += 1
            if record is not None:
                records.append(record)
                continue
            reasons[reason] += 1
            if len(errors) < self.cfg.max_error_samples:
                errors.append(RowError(line_number=number, reason=f"packet skipped: {reason}"))

        columns = list(self.schema.internal_columns)
        data = pd.DataFrame.from_records(records, columns=columns)
        if not data.empty:
            data = data.astype({"src_port": "int32", "dst_port": "int32", "packet_length": "int64"})
            data["timestamp"] = pd.to_datetime(data["timestamp"]).astype("datetime64[ns]")
            data["protocol"] = data["protocol"].astype("category")
            data = data.sort_values("timestamp", kind="mergesort").reset_index(drop=True)
        else:
            data = data.astype({"timestamp": "datetime64[ns]"})
        if reasons:
            logger.info("Skipped %d packet(s) in %s: %s", sum(reasons.values()), path,
                        ", ".join(f"{r} x{n}" for r, n in reasons.most_common(5)))
        return ParseResult(
            data=data,
            source=path,
            total_rows=total,
            valid_rows=len(data),
            errors=errors,
            profile="pcap",
            profile_description="Packet capture (pcap/pcapng via dpkt)",
            auto_detected=True,
            headerless=True,
            column_mapping={},
        )


def parse_pcap_file(path: Path | str, config: AppConfig = CONFIG) -> ParseResult:
    """Convenience function: parse a capture with :class:`PcapParser`."""
    return PcapParser(config).parse(path)


if __name__ == "__main__":  # pragma: no cover - manual smoke test
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    res = parse_pcap_file(sys.argv[1])
    print(f"{res.valid_rows}/{res.total_rows} packets decoded from {res.source}")
    print(res.data.head())
