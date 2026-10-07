"""
main.py - Command-line orchestrator for the Network Log & Anomaly Detector.

Pipeline::

    [--generate] mock data  ->  threat-intel feeds (V2)
                            ->  parse CSV / PCAP (V2) [streamed in chunks with --chunk-size (V2)]
                            ->  detection engine (rules + V2 detectors + ML)
                            ->  alerts.log (+ optional JSON)  ->  dashboard  ->  HTML report (V2)

Examples::

    python3 main.py --generate --dashboard          # end-to-end demo
    python3 main.py --input data/network_logs.csv   # analyse an existing file
    python3 main.py --input capture.pcap            # analyse a packet capture (V2)
    python3 main.py --chunk-size 50000 --report     # stream a big file, write HTML report (V2)
    python3 main.py --dashboard --live              # animated replay dashboard
    python3 main.py --no-ml --min-severity HIGH     # rules only, show HIGH alerts
    python3 main.py --streamlit                     # web dashboard (V2)

Every V2 feature is wrapped in ``try/except`` so a failure in an optional
component (feeds, report, streaming, ...) is reported as a warning and the V1
pipeline still completes.

Exit codes: 0 = success, 1 = input/parse error, 2 = invalid arguments.
"""

from __future__ import annotations

import argparse
import importlib.util
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import pandas as pd
from rich.console import Console
from rich.table import Table

from alerting import AlertManager, AlertType, Severity
from config import CONFIG, PROFILE_CHOICES, AppConfig, __version__
from dashboard import V2_ALERT_TYPES, Dashboard
from detection_engine import DetectionEngine, DetectionResult
from log_parser import LogParseError, LogParser, ParseResult
from mock_data_generator import generate_mock_data


def build_arg_parser() -> argparse.ArgumentParser:
    """Define the command-line interface."""
    parser = argparse.ArgumentParser(
        prog="network_anomaly_detector",
        description="Detect port scans, brute force, blacklisted traffic, DNS tunneling, "
                    "C2 beaconing, off-hours activity and ML anomalies in network logs.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    io = parser.add_argument_group("input / output")
    io.add_argument("-i", "--input", type=Path, default=CONFIG.paths.log_file,
                    help="CSV log file or .pcap/.pcapng capture to analyse")
    io.add_argument("-p", "--profile", choices=list(PROFILE_CHOICES), default="auto",
                    help="Input dataset format: auto-detect, CICIDS2017/CSE-CIC-IDS2018, "
                         "UNSW-NB15, or this tool's native format (ignored for pcap files)")
    io.add_argument("-a", "--alerts-log", type=Path, default=CONFIG.paths.alerts_log,
                    help="Alert log output file")
    io.add_argument("--append", action="store_true",
                    help="Append to the alert log instead of overwriting it")
    io.add_argument("--json", type=Path, nargs="?", const=CONFIG.paths.alerts_json, default=None,
                    help="Also export alerts as JSON (optional path)")
    io.add_argument("--report", type=Path, nargs="?", const=CONFIG.report.output_path, default=None,
                    help="Write a self-contained HTML report (optional path)")
    io.add_argument("--chunk-size", type=int, default=None, metavar="N",
                    help="Stream CSV input in chunks of N rows (constant memory for huge files)")

    gen = parser.add_argument_group("mock data")
    gen.add_argument("-g", "--generate", action="store_true",
                     help="Generate synthetic logs to --input before analysing")
    gen.add_argument("--rows", type=int, default=CONFIG.generator.total_rows,
                     help="Rows to generate with --generate")
    gen.add_argument("--seed", type=int, default=CONFIG.generator.random_seed,
                     help="Random seed for --generate")

    det = parser.add_argument_group("detection")
    det.add_argument("--no-ml", action="store_true", help="Disable Isolation Forest detection")
    det.add_argument("--contamination", type=float, default=CONFIG.ml.contamination,
                     help="Isolation Forest contamination (0 < c <= 0.5)")
    det.add_argument("--no-v2", action="store_true",
                     help="Disable the V2 detectors (DNS tunneling, beaconing, off-hours)")
    det.add_argument("--update-feeds", action="store_true",
                     help="Force a fresh download of the threat-intelligence feeds")
    det.add_argument("--no-threat-intel", action="store_true",
                     help="Do not load threat-intelligence feeds (static blacklist only)")

    out = parser.add_argument_group("display")
    out.add_argument("-d", "--dashboard", action="store_true", help="Show the Rich terminal dashboard")
    out.add_argument("--live", action="store_true",
                     help="With --dashboard: replay the capture as an animated live view")
    out.add_argument("--min-severity", choices=[s.value for s in Severity], default="LOW",
                     help="Minimum severity printed in the console alert list")
    out.add_argument("-q", "--quiet", action="store_true", help="Suppress console alert listing")
    out.add_argument("--streamlit", action="store_true",
                     help="Launch the Streamlit web dashboard instead of the CLI pipeline")
    return parser


def print_alert_list(console: Console, manager: AlertManager, min_severity: Severity) -> None:
    """Print a compact, colour-coded list of alerts at/above ``min_severity``."""
    alerts = manager.filter(min_severity=min_severity)
    table = Table(title=f"Alerts (severity ≥ {min_severity.value}): {len(alerts)}",
                  show_lines=False, expand=True)
    table.add_column("Time", no_wrap=True, style="dim")
    table.add_column("Sev", no_wrap=True)
    table.add_column("Type", no_wrap=True)
    table.add_column("Source → Destination", no_wrap=True)
    table.add_column("Description")
    for a in alerts:
        table.add_row(a.timestamp.strftime("%H:%M:%S"), f"[{a.severity.color}]{a.severity.value}[/]",
                      a.alert_type.value, f"{a.source_ip} → {a.dest_ip}", a.description)
    console.print(table)


# --------------------------------------------------------------------------- #
# V2 helpers (each one is fail-safe)
# --------------------------------------------------------------------------- #
def launch_streamlit(console: Console) -> int:
    """Start ``streamlit run streamlit_app.py`` and return its exit code."""
    app = Path(__file__).resolve().with_name("streamlit_app.py")
    if importlib.util.find_spec("streamlit") is None:
        console.print("[bold red]✘ Streamlit is not installed.[/] Run: pip install -r requirements.txt")
        return 1
    console.print(f"[green]✔[/] Launching Streamlit dashboard ({app.name}) - press Ctrl+C to stop.")
    return subprocess.call([sys.executable, "-m", "streamlit", "run", str(app)])


def load_threat_intel(console: Console, config: AppConfig, args: argparse.Namespace
                      ) -> Tuple[Dict[str, str], Optional[str]]:
    """Load threat-intel feed entries; on any failure fall back to the static blacklist."""
    if args.no_threat_intel or not config.threat_feeds.enabled:
        return {}, "disabled (static blacklist only)"
    try:
        from threat_intel import ThreatIntelManager

        manager = ThreatIntelManager(config)
        label = "Updating" if args.update_feeds else "Loading"
        with console.status(f"{label} threat-intelligence feeds..."):
            entries = manager.update_feeds() if args.update_feeds else manager.load()
        summary = manager.summary()
        style = "green]✔" if entries else "yellow]⚠"
        console.print(f"[{style}[/] {summary}")
        for status in manager.status:
            if status.error:
                console.print(f"  [dim]{status.name}: {status.error}[/]")
        return entries, summary.replace("Threat intel: ", "", 1)
    except Exception as exc:  # noqa: BLE001 - never block the pipeline on feeds
        console.print(f"[yellow]⚠ Threat-intel feeds unavailable ({exc}); using static blacklist only.[/]")
        return {}, "unavailable (static blacklist only)"


def _is_pcap(path: Path, config: AppConfig) -> bool:
    """Fail-safe wrapper around :func:`pcap_parser.is_pcap_file`."""
    try:
        from pcap_parser import is_pcap_file

        return is_pcap_file(path, config)
    except Exception:  # noqa: BLE001 - treat as CSV if detection itself fails
        return False


def build_engine(console: Console, config: AppConfig, args: argparse.Namespace,
                 intel: Dict[str, str]) -> DetectionEngine:
    """Create the detection engine; retries without V2 extras if construction fails."""
    try:
        enable_v2 = not args.no_v2
        return DetectionEngine(config, enable_ml=not args.no_ml, enable_dns=enable_v2,
                               enable_beaconing=enable_v2, enable_time_of_day=enable_v2,
                               threat_intel=intel or None)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[yellow]⚠ V2 detectors could not be initialised ({exc}); running V1 rules only.[/]")
        return DetectionEngine(config, enable_ml=not args.no_ml, enable_dns=False,
                               enable_beaconing=False, enable_time_of_day=False)


def run_streaming(console: Console, config: AppConfig, args: argparse.Namespace,
                  engine: DetectionEngine) -> Optional[Tuple[ParseResult, DetectionResult, int]]:
    """Stream the CSV through the engine. Returns None if streaming failed (caller falls back).

    Raises:
        LogParseError: For unreadable input (same behaviour as batch mode).
    """
    try:
        from streaming import StreamingProcessor

        keep = bool(args.dashboard or args.report)
        processor = StreamingProcessor(config, engine=engine, chunk_size=args.chunk_size)
        with console.status(f"Streaming {args.input} in chunks of {args.chunk_size:,} rows..."):
            res = processor.process(args.input, dataset_profile=args.profile, keep_data=keep)
    except LogParseError:
        raise
    except Exception as exc:  # noqa: BLE001
        console.print(f"[yellow]⚠ Streaming mode failed ({exc}); falling back to batch mode.[/]")
        return None
    data = res.data if res.data is not None else pd.DataFrame()
    parsed = ParseResult(data=data, source=res.source, total_rows=res.total_rows,
                         valid_rows=res.valid_rows, errors=res.errors, profile=res.profile,
                         profile_description=res.profile_description,
                         auto_detected=res.auto_detected)
    return parsed, res.detection, res.chunks


def write_report(console: Console, config: AppConfig, path: Path, parsed: ParseResult,
                 alerts: List, source: str, warnings: Sequence[str]) -> None:
    """Render the HTML report; failures are reported but never abort the run."""
    try:
        from report_generator import HTMLReportGenerator

        stats = {"total_rows": parsed.total_rows, "invalid_rows": parsed.invalid_rows,
                 "profile": parsed.profile_description or parsed.profile}
        target = HTMLReportGenerator(config).write(path, parsed.data, alerts, source=source,
                                                   parse_stats=stats, warnings=warnings)
        console.print(f"[green]✔[/] HTML report → {target}")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[yellow]⚠ HTML report could not be generated: {exc}[/]")


def _v2_summary(alerts: Sequence) -> str:
    """'DNS tunneling 1, C2 beaconing 0, ...' for the console."""
    counts = {t: 0 for t in V2_ALERT_TYPES}
    for a in alerts:
        if a.alert_type in counts:
            counts[a.alert_type] += 1
    return ", ".join(f"{t.label} {n}" for t, n in counts.items())


# --------------------------------------------------------------------------- #
# Pipeline
# --------------------------------------------------------------------------- #
def run(argv: Optional[Sequence[str]] = None) -> int:
    """Execute the full pipeline. Returns a process exit code."""
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    console = Console()

    if args.streamlit:
        return launch_streamlit(console)
    if not 0 < args.contamination <= 0.5:
        parser.error("--contamination must be in the range (0, 0.5]")  # exits with code 2
    if args.chunk_size is not None and args.chunk_size <= 0:
        parser.error("--chunk-size must be a positive integer")
    if args.live and not args.dashboard:
        console.print("[yellow]--live implies --dashboard; enabling dashboard.[/]")
        args.dashboard = True

    config: AppConfig = replace(CONFIG, ml=replace(CONFIG.ml, contamination=args.contamination))

    # 1. Optional mock data generation ---------------------------------- #
    if args.generate:
        with console.status("Generating synthetic network logs..."):
            summary = generate_mock_data(args.input, args.rows, args.seed, config=config)
        injected = ", ".join(f"{k}={v}" for k, v in summary.anomaly_rows.items())
        console.print(f"[green]✔[/] Generated {summary.total_rows:,} rows → {summary.output_path}")
        console.print(f"  [dim]injected anomalies: {injected}; malformed rows: {summary.malformed_rows}[/]")

    # 2. Threat intelligence (V2) ---------------------------------------- #
    intel, intel_summary = load_threat_intel(console, config, args)
    engine = build_engine(console, config, args, intel)

    # 3. Parse (+ detect when streaming) --------------------------------- #
    t0 = time.perf_counter()
    result: Optional[DetectionResult] = None
    streamed: Optional[Tuple[ParseResult, DetectionResult, int]] = None
    is_pcap = _is_pcap(args.input, config)
    try:
        if is_pcap:
            from pcap_parser import PcapParser

            if args.chunk_size:
                console.print("[yellow]--chunk-size applies to CSV input only; reading the capture in one pass.[/]")
            with console.status("Decoding packet capture..."):
                parsed = PcapParser(config).parse(args.input)
        else:
            if args.chunk_size:
                streamed = run_streaming(console, config, args, engine)
            if streamed is not None:
                parsed, result, n_chunks = streamed
            else:
                parsed = LogParser(config, dataset_profile=args.profile).parse(args.input)
    except LogParseError as exc:
        console.print(f"[bold red]✘ {exc}[/]")
        if not args.input.exists():
            console.print("  Tip: run with [bold]--generate[/] to create sample data.")
        return 1
    except Exception as exc:  # noqa: BLE001 - e.g. a corrupt capture that dpkt cannot read
        console.print(f"[bold red]✘ Could not read {args.input}: {exc}[/]")
        return 1

    how = "auto-detected" if parsed.auto_detected else "selected"
    console.print(f"[green]✔[/] Dataset profile: [bold]{parsed.profile}[/] — "
                  f"{parsed.profile_description} ({how}{', headerless file' if parsed.headerless else ''})")
    if parsed.column_mapping:
        console.print("  [dim]column mapping: " + ", ".join(
            f"{src!r}→{dst}" for src, dst in parsed.column_mapping.items()) + "[/]")
    unit = "packets" if is_pcap else "rows"
    mode = f" in {n_chunks} chunk(s) (streaming)" if streamed is not None else ""
    console.print(f"[green]✔[/] Parsed {parsed.total_rows:,} {unit} from {parsed.source}{mode} "
                  f"({parsed.valid_rows:,} valid, {parsed.invalid_rows:,} rejected) "
                  f"in {time.perf_counter() - t0:.2f}s")
    for err in parsed.errors[:5]:
        console.print(f"  [dim]rejected {'packet' if is_pcap else 'line'} {err.line_number}: {err.reason}[/]")
    if parsed.invalid_rows > 5:
        console.print(f"  [dim]... and {parsed.invalid_rows - 5} more[/]")

    # 4. Detect ----------------------------------------------------------- #
    if result is None:
        with console.status("Running detection engine..."):
            result = engine.run(parsed.data)
    for warning in result.warnings:
        console.print(f"[yellow]⚠ {warning}[/]")
    timing = ", ".join(f"{k} {v:.2f}s" for k, v in result.timings.items())
    console.print(f"[green]✔[/] Detection complete: {len(result.rule_alerts)} rule alerts, "
                  f"{len(result.ml_alerts)} ML alerts ({timing})")
    if not args.no_v2 or any(a.alert_type is AlertType.THREAT_INTEL_HIT for a in result.alerts):
        console.print(f"  [dim]V2 detections: {_v2_summary(result.alerts)}[/]")

    # 5. Alert logging ---------------------------------------------------- #
    with AlertManager(args.alerts_log, overwrite=not args.append, config=config) as manager:
        manager.add_alerts(result.alerts)
        console.print(f"[green]✔[/] Wrote {len(manager)} alerts → {manager.log_path}")
        if args.json:
            console.print(f"[green]✔[/] Exported JSON → {manager.export_json(args.json)}")
        sev = manager.count_by_severity()
        console.print("  " + "  ".join(f"[{s.color}]{s.value}: {n}[/]" for s, n in sev.items()))

        if not args.quiet and not args.dashboard:
            print_alert_list(console, manager, Severity(args.min_severity))

        # 6. HTML report (V2) --------------------------------------------- #
        if args.report:
            write_report(console, config, args.report, parsed, manager.alerts,
                         str(args.input), result.warnings)

        # 7. Dashboard ---------------------------------------------------- #
        if args.dashboard:
            dash = Dashboard(config, console)
            stats = {"invalid": parsed.invalid_rows}
            if args.live:
                dash.live_replay(parsed.data, manager.alerts, source=str(args.input))
            else:
                dash.render(parsed.data, manager.alerts, source=str(args.input), parse_stats=stats,
                            intel_summary=intel_summary)
    return 0


def main() -> None:
    """Console entry point."""
    try:
        sys.exit(run())
    except KeyboardInterrupt:
        Console().print("\n[yellow]Interrupted by user.[/]")
        sys.exit(130)


if __name__ == "__main__":
    main()
