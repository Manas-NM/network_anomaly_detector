"""Tests for pcap_parser.py using tiny captures written with dpkt."""

from __future__ import annotations

import socket
from datetime import datetime
from pathlib import Path
from typing import List, Tuple

import pytest

dpkt = pytest.importorskip("dpkt")

from alerting import AlertType  # noqa: E402
from detection_engine import RuleBasedDetector  # noqa: E402
from log_parser import LogParseError  # noqa: E402
from pcap_parser import PcapParser, is_pcap_file  # noqa: E402

T0 = datetime(2026, 10, 5, 8, 0, 0).timestamp()


def ipv4(src: str, dst: str, proto: int, payload) -> "dpkt.ip.IP":
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=proto, data=payload)
    ip.len = len(ip)  # make sure the length field is set
    return ip


def tcp(sport: int, dport: int) -> "dpkt.tcp.TCP":
    return dpkt.tcp.TCP(sport=sport, dport=dport, flags=dpkt.tcp.TH_SYN)


def ether(ip) -> bytes:
    eth_type = dpkt.ethernet.ETH_TYPE_IP6 if isinstance(ip, dpkt.ip6.IP6) else dpkt.ethernet.ETH_TYPE_IP
    return bytes(dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x11" * 6, type=eth_type, data=ip))


def sample_packets() -> List[Tuple[float, bytes]]:
    ip6 = dpkt.ip6.IP6(src=socket.inet_pton(socket.AF_INET6, "2001:db8::1"),
                       dst=socket.inet_pton(socket.AF_INET6, "2001:db8::2"), nxt=17, hlim=64,
                       data=dpkt.udp.UDP(sport=5353, dport=53, data=b"q" * 12))
    ip6.plen = len(ip6.data)
    arp = bytes(dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\xff" * 6,
                                       type=dpkt.ethernet.ETH_TYPE_ARP, data=dpkt.arp.ARP()))
    return [
        (T0 + 0.0, ether(ipv4("10.0.0.5", "192.168.1.10", 6, tcp(40000, 443)))),
        (T0 + 0.5, ether(ipv4("10.0.0.5", "8.8.8.8", 17, dpkt.udp.UDP(sport=40001, dport=53, data=b"x" * 20)))),
        (T0 + 1.0, ether(ipv4("10.0.0.6", "10.0.0.1", 1, dpkt.icmp.ICMP(type=8, data=b"ping")))),
        (T0 + 1.5, ether(ip6)),
        (T0 + 2.0, arp),
    ]


def write_pcap(path: Path, packets, linktype: int = dpkt.pcap.DLT_EN10MB) -> Path:
    with path.open("wb") as fh:
        writer = dpkt.pcap.Writer(fh, linktype=linktype)
        for ts, buf in packets:
            writer.writepkt(buf, ts=ts)
    return path


def test_parse_ethernet_capture(tmp_path: Path) -> None:
    result = PcapParser().parse(write_pcap(tmp_path / "small.pcap", sample_packets()))
    assert result.total_rows == 5 and result.valid_rows == 4
    assert result.profile == "pcap"
    assert len(result.errors) == 1 and "non-IP" in result.errors[0].reason
    df = result.data
    assert df["protocol"].astype(str).tolist() == ["TCP", "UDP", "ICMP", "UDP"]
    assert df["dst_port"].tolist() == [443, 53, 0, 53]
    assert df["src_ip"].tolist()[-1] == "2001:db8::1"
    assert df["timestamp"].iloc[0] == datetime.fromtimestamp(T0)
    assert df["packet_length"].iloc[0] == 40  # 20-byte IPv4 + 20-byte TCP header
    assert df["packet_length"].iloc[3] == 40 + 8 + 12  # IPv6 header + UDP header + payload


def test_raw_ip_and_pcapng(tmp_path: Path) -> None:
    raw = [(T0, bytes(ipv4("10.0.0.7", "10.0.0.8", 6, tcp(1234, 22))))]
    assert PcapParser().parse(write_pcap(tmp_path / "raw.pcap", raw, dpkt.pcap.DLT_RAW)).valid_rows == 1

    path = tmp_path / "capture.bin"  # wrong extension on purpose: detection uses magic bytes
    with path.open("wb") as fh:
        writer = dpkt.pcapng.Writer(fh)
        for ts, buf in sample_packets():
            writer.writepkt(buf, ts=ts)
    assert is_pcap_file(path)
    assert PcapParser().parse(path).valid_rows == 4


def test_is_pcap_file(tmp_path: Path, native_csv: Path) -> None:
    assert not is_pcap_file(native_csv)
    assert is_pcap_file(tmp_path / "anything.pcap")  # extension alone is enough
    assert not is_pcap_file(tmp_path / "missing.bin")


def test_corrupt_and_missing_capture(tmp_path: Path) -> None:
    junk = tmp_path / "junk.pcap"
    junk.write_bytes(b"this is not a capture file")
    with pytest.raises(LogParseError):
        PcapParser().parse(junk)
    with pytest.raises(LogParseError, match="not found"):
        PcapParser().parse(tmp_path / "missing.pcap")


def test_truncated_capture_keeps_complete_packets(tmp_path: Path) -> None:
    path = write_pcap(tmp_path / "trunc.pcap", sample_packets())
    path.write_bytes(path.read_bytes()[:-10])  # cut the last record mid-packet
    result = PcapParser().parse(path)
    assert result.valid_rows == 4
    assert result.total_rows >= 5


def test_detectors_work_on_pcap_data(tmp_path: Path) -> None:
    scan = [(T0 + i * 0.05, ether(ipv4("203.0.113.9", "192.168.1.10", 6, tcp(40000 + i, 1 + i))))
            for i in range(30)]
    df = PcapParser().parse(write_pcap(tmp_path / "scan.pcap", scan)).data
    alerts = RuleBasedDetector().detect(df)
    assert [a.alert_type for a in alerts] == [AlertType.PORT_SCAN]
    assert alerts[0].details["unique_ports"] == 30
