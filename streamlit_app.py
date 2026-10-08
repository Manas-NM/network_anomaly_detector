"""
streamlit_app.py - Interactive web dashboard (V2).

Launch with either::

    streamlit run streamlit_app.py
    python3 main.py --streamlit

Features
--------
* Analyse the default log file, any CSV / pcap path, or an uploaded file.
* Sidebar filters: severity, alert type, time range and free-text search.
* Metric cards plus Plotly charts: alert timeline, protocol distribution,
  severity breakdown and top source IPs.
* Sortable alert table with CSV / JSON / HTML-report downloads.

The app only *reads* the analysis modules; it never modifies the CLI's
``alerts.log``.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pandas as pd
import plotly.express as px
import streamlit as st

from alerting import Alert, AlertType, Severity
from config import CONFIG, DATA_DIR, PROFILE_CHOICES, AppConfig, __version__
from report_generator import PALETTE, SEVERITY_HEX, HTMLReportGenerator

UPLOAD_DIR = DATA_DIR / "uploads"
SEVERITY_ORDER = [s.value for s in sorted(Severity, key=lambda s: -s.rank)]
TYPE_LABELS = {t.value: t.label for t in AlertType}


# --------------------------------------------------------------------------- #
# Analysis (cached)
# --------------------------------------------------------------------------- #
def _alerts_frame(alerts: List[Alert]) -> pd.DataFrame:
    """Convert alerts to a flat DataFrame for filtering and display."""
    rows = [{
        "Time": a.timestamp, "Severity": a.severity.value, "Type": a.alert_type.label,
        "Code": a.alert_type.value, "Method": a.alert_type.method, "Source IP": a.source_ip,
        "Destination": a.dest_ip, "Description": a.description,
    } for a in alerts]
    columns = ["Time", "Severity", "Type", "Code", "Method", "Source IP", "Destination", "Description"]
    frame = pd.DataFrame(rows, columns=columns)
    frame["Time"] = pd.to_datetime(frame["Time"])
    return frame


@st.cache_data(show_spinner="Analysing traffic...")
def analyse(path: str, mtime: float, profile: str, enable_ml: bool, enable_v2: bool,
            use_intel: bool) -> Tuple[pd.DataFrame, List[Alert], Dict[str, Any]]:
    """Parse ``path`` (CSV or pcap) and run the detection engine.

    ``mtime`` is only part of the cache key so edits to the file trigger a re-run.
    """
    from detection_engine import DetectionEngine
    from log_parser import LogParser
    from pcap_parser import PcapParser, is_pcap_file

    meta: Dict[str, Any] = {"warnings": [], "intel": "disabled"}
    config: AppConfig = CONFIG
    intel: Dict[str, str] = {}
    if use_intel:
        try:
            from threat_intel import ThreatIntelManager

            manager = ThreatIntelManager(config)
            intel = manager.load()
            meta["intel"] = manager.summary()
        except Exception as exc:  # noqa: BLE001 - feeds are optional
            meta["warnings"].append(f"Threat intel unavailable: {exc}")

    if is_pcap_file(path, config):
        parsed = PcapParser(config).parse(path)
    else:
        parsed = LogParser(config, dataset_profile=profile).parse(path)
    engine = DetectionEngine(config, enable_ml=enable_ml, enable_dns=enable_v2,
                             enable_beaconing=enable_v2, enable_time_of_day=enable_v2,
                             threat_intel=intel or None)
    result = engine.run(parsed.data)
    meta.update({
        "profile": parsed.profile_description or parsed.profile,
        "total_rows": parsed.total_rows, "invalid_rows": parsed.invalid_rows,
        "rule_alerts": len(result.rule_alerts), "ml_alerts": len(result.ml_alerts),
        "timings": dict(result.timings),
    })
    meta["warnings"].extend(result.warnings)
    return parsed.data, list(result.alerts), meta


# --------------------------------------------------------------------------- #
# Sidebar
# --------------------------------------------------------------------------- #
def sidebar_source() -> Tuple[str, str, bool, bool, bool]:
    """Data-source controls. Returns ``(path, profile, ml, v2, intel)``."""
    st.sidebar.header("Data source")
    uploaded = st.sidebar.file_uploader("Upload a CSV or pcap file",
                                        type=["csv", "pcap", "pcapng", "cap"])
    path = st.sidebar.text_input("...or a file path", value=str(CONFIG.paths.log_file))
    if uploaded is not None:
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        target = UPLOAD_DIR / Path(uploaded.name).name
        data = bytes(uploaded.getbuffer())
        # Rewrite only when the content changed: rewriting bumps the mtime, which
        # busts the analysis cache and re-runs everything on every widget click.
        if not target.is_file() or target.stat().st_size != len(data) or target.read_bytes() != data:
            target.write_bytes(data)
        path = str(target)
    profile = st.sidebar.selectbox("Dataset format", list(PROFILE_CHOICES), index=0,
                                   help="'auto' detects native, CICIDS and UNSW-NB15 CSVs.")
    with st.sidebar.expander("Detection options"):
        enable_ml = st.checkbox("Machine learning (Isolation Forest)", value=True)
        enable_v2 = st.checkbox("V2 detectors (DNS, beaconing, off-hours)", value=True)
        use_intel = st.checkbox("Threat-intelligence feeds", value=True)
    if st.sidebar.button("Generate sample data", help=f"Writes {CONFIG.paths.log_file.name}"):
        from mock_data_generator import generate_mock_data

        summary = generate_mock_data(CONFIG.paths.log_file)
        st.sidebar.success(f"Generated {summary.total_rows:,} rows.")
        path = str(CONFIG.paths.log_file)
    return path, profile, enable_ml, enable_v2, use_intel


def sidebar_filters(alerts: pd.DataFrame) -> pd.DataFrame:
    """Severity / type / time / search filters. Returns the filtered alerts."""
    st.sidebar.header("Filters")
    severities = st.sidebar.multiselect("Severity", SEVERITY_ORDER, default=SEVERITY_ORDER)
    types = sorted(alerts["Type"].unique())
    chosen_types = st.sidebar.multiselect("Alert type", types, default=types)
    search = st.sidebar.text_input("Search (IP, text...)", value="").strip().lower()

    mask = alerts["Severity"].isin(severities) & alerts["Type"].isin(chosen_types)
    if not alerts.empty:
        start = alerts["Time"].min().to_pydatetime().replace(microsecond=0)
        end = alerts["Time"].max().to_pydatetime().replace(microsecond=0)
        if end > start:
            low, high = st.sidebar.slider("Time range", min_value=start, max_value=end,
                                          value=(start, end), format="MM-DD HH:mm:ss")
            upper = pd.Timestamp(high) + pd.Timedelta(seconds=1)
            mask &= (alerts["Time"] >= pd.Timestamp(low)) & (alerts["Time"] < upper)
    if search:
        haystack = alerts[["Source IP", "Destination", "Type", "Code", "Description"]].astype(str)
        mask &= haystack.apply(lambda col: col.str.lower().str.contains(search, regex=False)).any(axis=1)
    return alerts[mask]


# --------------------------------------------------------------------------- #
# Main page
# --------------------------------------------------------------------------- #
def metric_cards(df: pd.DataFrame, alerts: pd.DataFrame) -> None:
    """Top-row KPI cards."""
    sev = alerts["Severity"].value_counts()
    cols = st.columns(6)
    cols[0].metric("Records analysed", f"{len(df):,}", border=True)
    cols[1].metric("Alerts (filtered)", f"{len(alerts):,}", border=True)
    cols[2].metric("🔴 High", int(sev.get("HIGH", 0)), border=True)
    cols[3].metric("🟠 Medium", int(sev.get("MEDIUM", 0)), border=True)
    cols[4].metric("🟢 Low", int(sev.get("LOW", 0)), border=True)
    cols[5].metric("Flagged source IPs", alerts["Source IP"].nunique(), border=True)


def charts(df: pd.DataFrame, alerts: pd.DataFrame) -> None:
    """Timeline, protocol, severity and top-source charts."""
    if alerts.empty:
        st.info("No alerts match the current filters.")
    else:
        fig = px.histogram(alerts, x="Time", color="Severity", nbins=60,
                           category_orders={"Severity": SEVERITY_ORDER},
                           color_discrete_map=SEVERITY_HEX, title="Alert timeline")
        fig.update_layout(bargap=0.05, height=320, margin=dict(t=50, b=10))
        st.plotly_chart(fig, width="stretch")

    left, middle, right = st.columns(3)
    with left:
        if not df.empty:
            proto = df["protocol"].astype(str).value_counts().reset_index()
            proto.columns = ["Protocol", "Records"]
            fig = px.pie(proto, names="Protocol", values="Records", hole=0.45,
                         title="Protocol distribution", color_discrete_sequence=list(PALETTE))
            fig.update_layout(height=340, margin=dict(t=50, b=10))
            st.plotly_chart(fig, width="stretch")
    with middle:
        sev = (alerts["Severity"].value_counts().reindex(SEVERITY_ORDER, fill_value=0)
               .rename_axis("Severity").reset_index(name="Alerts"))
        fig = px.bar(sev, x="Severity", y="Alerts", color="Severity", title="Alerts by severity",
                     color_discrete_map=SEVERITY_HEX, text="Alerts")
        fig.update_layout(height=340, showlegend=False, margin=dict(t=50, b=10))
        st.plotly_chart(fig, width="stretch")
    with right:
        top = (alerts.groupby("Source IP").size().nlargest(10).sort_values()
               .rename("Alerts").reset_index())
        fig = px.bar(top, x="Alerts", y="Source IP", orientation="h", title="Top source IPs (alerts)",
                     color_discrete_sequence=[PALETTE[1]])
        fig.update_layout(height=340, margin=dict(t=50, b=10))
        st.plotly_chart(fig, width="stretch")


def alert_table(df: pd.DataFrame, alerts: pd.DataFrame, all_alerts: List[Alert],
                meta: Dict[str, Any], source: str) -> None:
    """Sortable alert table and download buttons."""
    st.subheader(f"Alerts ({len(alerts):,})")
    view = alerts.sort_values(["Time"]).drop(columns=["Code"])
    st.dataframe(view, width="stretch", hide_index=True, height=420,
                 column_config={"Time": st.column_config.DatetimeColumn(format="YYYY-MM-DD HH:mm:ss"),
                                "Description": st.column_config.TextColumn(width="large")})

    selected = [all_alerts[i] for i in alerts.index]  # frame index == position in all_alerts
    c1, c2, c3 = st.columns(3)
    c1.download_button("⬇ Filtered alerts (CSV)", view.to_csv(index=False).encode("utf-8"),
                       file_name="alerts.csv", mime="text/csv")
    c2.download_button("⬇ Filtered alerts (JSON)", view.to_json(orient="records", date_format="iso"),
                       file_name="alerts.json", mime="application/json")
    try:
        html = HTMLReportGenerator(CONFIG).render(
            df, selected, source=source, warnings=meta.get("warnings"),
            parse_stats={"total_rows": meta.get("total_rows", len(df)),
                         "invalid_rows": meta.get("invalid_rows", 0), "profile": meta.get("profile", "")})
        c3.download_button("⬇ HTML report", html, file_name="report.html", mime="text/html")
    except Exception as exc:  # noqa: BLE001 - report is optional
        c3.warning(f"HTML report unavailable: {exc}")


def main() -> None:
    """Streamlit entry point."""
    st.set_page_config(page_title="Network Anomaly Detector", page_icon="🛡️", layout="wide")
    st.title("🛡️ Network Log & Anomaly Detector")
    st.caption(f"Version {__version__} - rule-based, V2 behavioural and machine-learning detection")

    path, profile, enable_ml, enable_v2, use_intel = sidebar_source()
    file = Path(path).expanduser()
    if not file.is_file():
        st.warning(f"File not found: `{file}`. Use **Generate sample data** in the sidebar "
                   "or enter a valid path.")
        return
    try:
        df, alerts, meta = analyse(str(file), file.stat().st_mtime, profile, enable_ml,
                                   enable_v2, use_intel)
    except Exception as exc:  # noqa: BLE001 - show parse errors in the UI
        st.error(f"Could not analyse `{file}`: {exc}")
        return

    # Same order as _alerts_frame index -> used to map filtered rows back to Alert objects.
    alerts = sorted(alerts, key=lambda a: a.timestamp)
    frame = _alerts_frame(alerts)
    filtered = sidebar_filters(frame)

    st.caption(f"Source: `{file}` · Format: {meta.get('profile', '-')} · "
               f"{meta.get('total_rows', 0):,} rows read, {meta.get('invalid_rows', 0):,} rejected · "
               f"{meta.get('intel')}")
    for warning in meta.get("warnings", []):
        st.warning(warning)

    metric_cards(df, filtered)
    charts(df, filtered)
    alert_table(df, filtered, alerts, meta, str(file))
    st.caption(f"Rendered {datetime.now():%Y-%m-%d %H:%M:%S}")


# Streamlit executes the script top-to-bottom, so call main() unconditionally
# when run via `streamlit run` (``__name__`` is "__main__" there as well).
if __name__ == "__main__":
    main()
