"""Tests for detection_engine.py: V1 rules, V2 detectors, ML and the combined engine."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta
from typing import List

import pandas as pd
import pytest

from alerting import AlertType, Severity
from config import CONFIG
from detection_engine import (BeaconingDetector, DetectionEngine, DNSTunnelingDetector,
                              MLAnomalyDetector, RuleBasedDetector, TimeOfDayDetector)
from tests.conftest import BASE, Row, background, make_df

ATTACKER, TARGET = "203.0.113.9", "192.168.1.200"


def of_type(alerts, alert_type: AlertType) -> List:
    return [a for a in alerts if a.alert_type is alert_type]


def scan_rows(n_ports: int, span: float = 2.0) -> List[Row]:
    return [(BASE + timedelta(seconds=60 + span * i / n_ports), ATTACKER, TARGET, 40000 + i, 1 + i, "TCP", 60)
            for i in range(n_ports)]


def burst_rows(n: int, port: int = 22, span: float = 5.0, src: str = ATTACKER) -> List[Row]:
    return [(BASE + timedelta(seconds=120 + span * i / n), src, TARGET, 50000 + i, port, "TCP", 80)
            for i in range(n)]


def dns_rows(n: int, span: float, src: str = "10.0.0.99") -> List[Row]:
    return [(BASE + timedelta(seconds=30 + span * i / n), src, "192.168.1.53", 30000 + i, 53, "UDP", 90)
            for i in range(n)]


def beacon_rows(n: int, interval: float, jitter: float = 0.1, src: str = "10.0.0.77",
                dst: str = "203.0.113.150") -> List[Row]:
    return [(BASE + timedelta(seconds=interval * i + (jitter if i % 2 else -jitter)), src, dst,
             45000 + i, 443, "TCP", 300) for i in range(n)]


def off_hours_rows(n: int, hour: int = 3, src: str = "10.0.0.88") -> List[Row]:
    start = BASE.replace(hour=hour)
    return [(start + timedelta(seconds=10 * i), src, "192.168.1.5", 46000 + i, 445, "TCP", 500)
            for i in range(n)]


# --------------------------------------------------------------------------- #
# V1 rules
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("ports,expected", [(10, None), (15, Severity.MEDIUM), (60, Severity.HIGH)])
def test_port_scan(ports: int, expected) -> None:
    alerts = of_type(RuleBasedDetector().detect(make_df(background() + scan_rows(ports))), AlertType.PORT_SCAN)
    if expected is None:
        assert alerts == []
    else:
        assert len(alerts) == 1
        assert alerts[0].severity is expected
        assert (alerts[0].source_ip, alerts[0].dest_ip) == (ATTACKER, TARGET)
        assert alerts[0].details["unique_ports"] == ports


def test_slow_scan_below_window_not_flagged() -> None:
    df = make_df(background() + scan_rows(15, span=120.0))  # 15 ports over 2 minutes
    assert of_type(RuleBasedDetector().detect(df), AlertType.PORT_SCAN) == []


@pytest.mark.parametrize("n,expected", [(20, None), (25, Severity.MEDIUM), (45, Severity.HIGH)])
def test_brute_force(n: int, expected) -> None:
    alerts = of_type(RuleBasedDetector().detect(make_df(background() + burst_rows(n))), AlertType.BRUTE_FORCE)
    if expected is None:
        assert alerts == []
    else:
        assert len(alerts) == 1 and alerts[0].severity is expected
        assert alerts[0].details["dst_port"] == 22


def test_brute_force_ignores_unmonitored_ports() -> None:
    df = make_df(background() + burst_rows(45, port=8081))
    assert of_type(RuleBasedDetector().detect(df), AlertType.BRUTE_FORCE) == []


def test_blacklist_directions() -> None:
    rows = background() + [
        (BASE + timedelta(seconds=5), "10.0.0.5", "192.0.2.66", 50001, 443, "TCP", 300),      # outbound
        (BASE + timedelta(seconds=6), "198.51.100.130", "10.0.0.6", 443, 50002, "TCP", 300),  # inbound (CIDR)
    ]
    alerts = of_type(RuleBasedDetector().detect(make_df(rows)), AlertType.BLACKLISTED_IP)
    by_ip = {a.details["blacklisted_ip"]: a for a in alerts}
    assert set(by_ip) == {"192.0.2.66", "198.51.100.130"}
    assert by_ip["192.0.2.66"].severity is Severity.HIGH
    assert by_ip["192.0.2.66"].details["direction"] == "outbound"
    assert by_ip["198.51.100.130"].severity is Severity.MEDIUM


def test_threat_intel_hit_vs_static_blacklist() -> None:
    detector = RuleBasedDetector(extra_blacklist={"45.9.9.9": "feodo", "100.64.0.0/24": "et",
                                                  "garbage": "x", "192.0.2.66": "et"})
    assert detector.threat_intel_size == 3  # invalid entry ignored
    rows = background() + [
        (BASE + timedelta(seconds=5), "10.0.0.5", "45.9.9.9", 50001, 443, "TCP", 300),
        (BASE + timedelta(seconds=6), "100.64.0.20", "10.0.0.6", 443, 50002, "TCP", 300),
        (BASE + timedelta(seconds=7), "10.0.0.7", "192.0.2.66", 50003, 443, "TCP", 300),
    ]
    alerts = detector.detect(make_df(rows))
    intel = {a.details["blacklisted_ip"]: a for a in of_type(alerts, AlertType.THREAT_INTEL_HIT)}
    assert set(intel) == {"45.9.9.9", "100.64.0.20"}
    assert intel["45.9.9.9"].details["threat_feed"] == "feodo"
    assert intel["45.9.9.9"].severity is Severity.HIGH
    assert intel["100.64.0.20"].severity is Severity.MEDIUM
    # Static blacklist matches keep their V1 type even if a feed lists them too.
    assert [a.details["blacklisted_ip"] for a in of_type(alerts, AlertType.BLACKLISTED_IP)] == ["192.0.2.66"]


def test_benign_traffic_raises_no_rule_alerts(benign_df: pd.DataFrame) -> None:
    engine = DetectionEngine(enable_ml=False)
    assert engine.run(benign_df).alerts == []


# --------------------------------------------------------------------------- #
# V2 detectors
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("n,span,expected", [(40, 30.0, None), (60, 30.0, Severity.MEDIUM),
                                             (130, 55.0, Severity.HIGH)])
def test_dns_tunneling(n: int, span: float, expected) -> None:
    alerts = DNSTunnelingDetector().detect(make_df(background() + dns_rows(n, span)))
    if expected is None:
        assert alerts == []
    else:
        assert len(alerts) == 1
        a = alerts[0]
        assert a.alert_type is AlertType.DNS_TUNNELING and a.severity is expected
        assert a.source_ip == "10.0.0.99" and a.dest_ip == "192.168.1.53"
        assert a.details["queries"] == n


def test_dns_spread_out_not_flagged() -> None:
    # 120 queries spread over 10 minutes never exceed 50 per minute.
    assert DNSTunnelingDetector().detect(make_df(background() + dns_rows(120, 600.0))) == []


def test_beaconing_high() -> None:
    alerts = BeaconingDetector().detect(make_df(background() + beacon_rows(40, 30.0)))
    assert len(alerts) == 1
    a = alerts[0]
    assert a.alert_type is AlertType.BEACONING and a.severity is Severity.HIGH
    assert (a.source_ip, a.dest_ip) == ("10.0.0.77", "203.0.113.150")
    assert a.details["mean_interval_seconds"] == pytest.approx(30.0, abs=0.1)
    assert a.details["std_interval_seconds"] < 0.5


def test_beaconing_medium_with_few_connections() -> None:
    alerts = BeaconingDetector().detect(make_df(beacon_rows(15, 60.0)))
    assert len(alerts) == 1 and alerts[0].severity is Severity.MEDIUM


def test_beaconing_ignores_irregular_and_flood_traffic() -> None:
    irregular = [(BASE + timedelta(seconds=s), "10.0.0.70", "203.0.113.151", 45000 + i, 443, "TCP", 300)
                 for i, s in enumerate([0, 3, 40, 41, 90, 200, 205, 260, 400, 401, 500, 620, 700, 703])]
    flood = beacon_rows(200, 0.1, jitter=0.0, src="10.0.0.71")  # collapses into one session
    assert BeaconingDetector().detect(make_df(irregular + flood)) == []


def test_off_hours_thresholds() -> None:
    det = TimeOfDayDetector()
    assert det.detect(make_df(background() + off_hours_rows(100))) == []
    medium = det.detect(make_df(background() + off_hours_rows(150)))
    assert len(medium) == 1 and medium[0].severity is Severity.MEDIUM
    assert medium[0].details["off_hours_window"] == "22:00-06:00"
    high = det.detect(make_df(off_hours_rows(600)))
    assert len(high) == 1 and high[0].severity is Severity.HIGH


def test_business_hours_traffic_not_flagged() -> None:
    assert TimeOfDayDetector().detect(make_df(off_hours_rows(300, hour=10))) == []


def test_off_hours_window_wrapping_midnight() -> None:
    config = replace(CONFIG, time_of_day=replace(CONFIG.time_of_day, business_hours_start=20,
                                                 business_hours_end=4))
    det = TimeOfDayDetector(config)
    ts = pd.Series(pd.to_datetime([datetime(2026, 10, 5, h) for h in (1, 4, 12, 19, 21)]))
    assert det.off_hours_mask(ts).tolist() == [False, True, True, True, False]


# --------------------------------------------------------------------------- #
# ML + engine
# --------------------------------------------------------------------------- #
def test_ml_flags_jumbo_packets() -> None:
    jumbo = [(BASE + timedelta(seconds=300 + i), "10.0.0.250", "93.184.216.200", 51000 + i, 443, "TCP", 64000)
             for i in range(5)]
    alerts, scored = MLAnomalyDetector().detect(make_df(background() + jumbo))
    assert len(scored) == 205 and "anomaly_score" in scored
    assert "10.0.0.250" in {a.source_ip for a in alerts}
    assert all(a.alert_type is AlertType.ML_ANOMALY for a in alerts)


def test_ml_too_few_samples_is_a_warning() -> None:
    result = DetectionEngine().run(make_df(background(20)))
    assert any("ML detection skipped" in w for w in result.warnings)


def test_engine_empty_input() -> None:
    result = DetectionEngine().run(make_df([]))
    assert result.alerts == [] and result.warnings == ["No records to analyse."]


def test_engine_combines_v1_and_v2_and_corroborates() -> None:
    rows = background() + scan_rows(60) + dns_rows(130, 55.0) + beacon_rows(40, 30.0) + off_hours_rows(150)
    result = DetectionEngine().run(make_df(rows))
    types = {a.alert_type for a in result.rule_alerts}
    assert {AlertType.PORT_SCAN, AlertType.DNS_TUNNELING, AlertType.BEACONING,
            AlertType.TIME_OF_DAY_ANOMALY} <= types
    assert result.alerts == sorted(result.alerts, key=lambda a: (a.timestamp, -a.severity.rank))
    assert {"rules", "dns", "beaconing", "time_of_day", "ml"} <= set(result.timings)
    for alert in result.ml_alerts:
        if alert.source_ip == ATTACKER:
            assert "PORT_SCAN" in alert.details["corroborated_by"]


def test_v2_detectors_can_be_disabled() -> None:
    rows = background() + dns_rows(130, 55.0) + beacon_rows(40, 30.0) + off_hours_rows(150)
    engine = DetectionEngine(enable_ml=False, enable_dns=False, enable_beaconing=False,
                             enable_time_of_day=False)
    assert engine.run(make_df(rows)).alerts == []


def test_v2_failure_never_breaks_v1(monkeypatch) -> None:
    engine = DetectionEngine(enable_ml=False)

    def boom(df):
        raise RuntimeError("detector exploded")

    for _, detector in engine.v2_detectors:
        monkeypatch.setattr(detector, "detect", boom)
    result = engine.run(make_df(background() + scan_rows(60)))
    assert of_type(result.alerts, AlertType.PORT_SCAN)
    assert sum("detector exploded" in w for w in result.warnings) == 3
