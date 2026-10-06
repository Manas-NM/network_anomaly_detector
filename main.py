"""
main.py - Command-line orchestrator for the Network Log & Anomaly Detector.

Pipeline::

    [--generate] mock data  ->  parse CSV  ->  detection engine (rules + ML)
                            ->  alerts.log (+ optional JSON)  ->  dashboard

Examples::

    python main.py --generate --dashboard          # end-to-end demo
    python main.py --input data/network_logs.csv   # analyse an existing file
    python main.py --dashboard --live              # animated replay dashboard
    python main.py --no-ml --min-severity HIGH     # rules only, show HIGH alerts

Exit codes: 0 = success, 1 = input/parse error, 2 = invalid arguments.
"""

from __future__ import annotations

import argparse
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Optional, Sequence

from rich.console import Console
from rich.table import Table

from alerting import AlertManager, Severity
from config import CONFIG, AppConfig
from dashboard import Dashboard
from detection_engine import DetectionEngine
from log_parser import LogParseError, LogParser
from mock_data_generator import generate_mock_data


def build_arg_parser() -> argparse.ArgumentParser:
    """Define the command-line interface."""
    parser = argparse.ArgumentParser(
        prog="network_anomaly_detector",
        description="Detect port scans, brute force, blacklisted traffic and ML anomalies in network logs.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    io = parser.add_argument_group("input / output")
    io.add_argument("-i", "--input", type=Path, default=CONFIG.paths.log_file,
                    help="CSV log file to analyse")
    io.add_argument("-a", "--alerts-log", type=Path, default=CONFIG.paths.alerts_log,
                    help="Alert log output file")
    io.add_argument("--append", action="store_true",
                    help="Append to the alert log instead of overwriting it")
    io.add_argument("--json", type=Path, nargs="?", const=CONFIG.paths.alerts_json, default=None,
                    help="Also export alerts as JSON (optional path)")

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

    out = parser.add_argument_group("display")
    out.add_argument("-d", "--dashboard", action="store_true", help="Show the Rich terminal dashboard")
    out.add_argument("--live", action="store_true",
                     help="With --dashboard: replay the capture as an animated live view")
    out.add_argument("--min-severity", choices=[s.value for s in Severity], default="LOW",
                     help="Minimum severity printed in the console alert list")
    out.add_argument("-q", "--quiet", action="store_true", help="Suppress console alert listing")
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


def run(argv: Optional[Sequence[str]] = None) -> int:
    """Execute the full pipeline. Returns a process exit code."""
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    console = Console()

    if not 0 < args.contamination <= 0.5:
        parser.error("--contamination must be in the range (0, 0.5]")  # exits with code 2
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

    # 2. Parse ------------------------------------------------------------ #
    t0 = time.perf_counter()
    try:
        parsed = LogParser(config).parse(args.input)
    except LogParseError as exc:
        console.print(f"[bold red]✘ {exc}[/]")
        if not args.input.exists():
            console.print("  Tip: run with [bold]--generate[/] to create sample data.")
        return 1
    console.print(f"[green]✔[/] Parsed {parsed.total_rows:,} rows from {parsed.source} "
                  f"({parsed.valid_rows:,} valid, {parsed.invalid_rows} rejected) "
                  f"in {time.perf_counter() - t0:.2f}s")
    for err in parsed.errors[:5]:
        console.print(f"  [dim]rejected line {err.line_number}: {err.reason}[/]")
    if parsed.invalid_rows > 5:
        console.print(f"  [dim]... and {parsed.invalid_rows - 5} more[/]")

    # 3. Detect ----------------------------------------------------------- #
    engine = DetectionEngine(config, enable_ml=not args.no_ml)
    with console.status("Running detection engine..."):
        result = engine.run(parsed.data)
    for warning in result.warnings:
        console.print(f"[yellow]⚠ {warning}[/]")
    timing = ", ".join(f"{k} {v:.2f}s" for k, v in result.timings.items())
    console.print(f"[green]✔[/] Detection complete: {len(result.rule_alerts)} rule alerts, "
                  f"{len(result.ml_alerts)} ML alerts ({timing})")

    # 4. Alert logging ---------------------------------------------------- #
    with AlertManager(args.alerts_log, overwrite=not args.append, config=config) as manager:
        manager.add_alerts(result.alerts)
        console.print(f"[green]✔[/] Wrote {len(manager)} alerts → {manager.log_path}")
        if args.json:
            console.print(f"[green]✔[/] Exported JSON → {manager.export_json(args.json)}")
        sev = manager.count_by_severity()
        console.print("  " + "  ".join(f"[{s.color}]{s.value}: {n}[/]" for s, n in sev.items()))

        if not args.quiet and not args.dashboard:
            print_alert_list(console, manager, Severity(args.min_severity))

        # 5. Dashboard ---------------------------------------------------- #
        if args.dashboard:
            dash = Dashboard(config, console)
            stats = {"invalid": parsed.invalid_rows}
            if args.live:
                dash.live_replay(parsed.data, manager.alerts, source=str(args.input))
            else:
                dash.render(parsed.data, manager.alerts, source=str(args.input), parse_stats=stats)
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
