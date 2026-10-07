"""Tests for alerting.py: severities, alert types, log output and JSON export."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

from alerting import Alert, AlertManager, AlertType, Severity
from tests.conftest import BASE


def make_alert(offset: int = 0, severity: Severity = Severity.HIGH,
               alert_type: AlertType = AlertType.PORT_SCAN, src: str = "203.0.113.9") -> Alert:
    return Alert(timestamp=BASE + timedelta(seconds=offset), alert_type=alert_type, severity=severity,
                 source_ip=src, dest_ip="192.168.1.10", description=f"{alert_type.label} test",
                 details={"events": offset, "when": BASE})


def test_severity_ordering_and_colours() -> None:
    assert [s.rank for s in (Severity.LOW, Severity.MEDIUM, Severity.HIGH)] == [1, 2, 3]
    assert Severity.HIGH.color == "bold red"
    assert Severity("MEDIUM") is Severity.MEDIUM


def test_alert_type_method_and_labels() -> None:
    assert AlertType.ML_ANOMALY.method == "ML"
    assert all(t.method == "Rule" for t in AlertType if t is not AlertType.ML_ANOMALY)
    assert AlertType.DNS_TUNNELING.label == "DNS tunneling"
    assert AlertType.BEACONING.label == "C2 beaconing"
    assert AlertType.TIME_OF_DAY_ANOMALY.label == "Off-hours activity"
    assert AlertType.THREAT_INTEL_HIT.label == "Threat intel hit"


def test_log_line_and_dict() -> None:
    alert = make_alert(5, alert_type=AlertType.DNS_TUNNELING)
    line = alert.to_log_line()
    assert line.startswith("2026-10-05 08:00:05.000 | HIGH")
    assert "DNS_TUNNELING" in line and "203.0.113.9 -> 192.168.1.10" in line
    data = alert.to_dict()
    assert data["alert_type"] == "DNS_TUNNELING" and data["severity"] == "HIGH"
    assert data["timestamp"] == "2026-10-05T08:00:05"


def test_manager_writes_log_and_filters(tmp_path: Path) -> None:
    log = tmp_path / "alerts.log"
    alerts = [make_alert(30, Severity.LOW, AlertType.ML_ANOMALY),
              make_alert(10, Severity.HIGH, AlertType.BEACONING),
              make_alert(20, Severity.MEDIUM, AlertType.TIME_OF_DAY_ANOMALY)]
    with AlertManager(log) as manager:
        assert manager.add_alerts(alerts) == 3
        assert [a.timestamp.second for a in manager.alerts] == [10, 20, 30]  # chronological
        assert len(manager.filter(min_severity=Severity.MEDIUM)) == 2
        assert manager.filter(alert_type=AlertType.BEACONING)[0].severity is Severity.HIGH
        assert manager.count_by_severity() == {Severity.LOW: 1, Severity.MEDIUM: 1, Severity.HIGH: 1}
        counts = manager.count_by_type()
        assert set(counts) == set(AlertType) and counts[AlertType.PORT_SCAN] == 0
        assert manager.recent(1)[0].timestamp.second == 30
    lines = log.read_text().splitlines()
    assert len(lines) == 3
    assert "BEACONING" in lines[0] and "OFF" not in lines[0]


def test_overwrite_and_append(tmp_path: Path) -> None:
    log = tmp_path / "alerts.log"
    with AlertManager(log) as m:
        m.add_alert(make_alert(1))
    with AlertManager(log, overwrite=False) as m:
        m.add_alert(make_alert(2))
    assert len(log.read_text().splitlines()) == 2
    with AlertManager(log) as m:
        m.add_alert(make_alert(3))
    assert len(log.read_text().splitlines()) == 1


def test_export_json_round_trip(tmp_path: Path) -> None:
    with AlertManager(tmp_path / "alerts.log") as m:
        m.add_alerts([make_alert(1, alert_type=AlertType.THREAT_INTEL_HIT), make_alert(2)])
        path = m.export_json(tmp_path / "out" / "alerts.json")
    data = json.loads(path.read_text())
    assert [d["alert_type"] for d in data] == ["THREAT_INTEL_HIT", "PORT_SCAN"]
    assert data[0]["details"]["when"] == str(BASE)  # non-JSON types are stringified
