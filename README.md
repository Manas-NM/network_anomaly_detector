# 🛡️ Network Log & Anomaly Detector

A modular Python tool for spotting suspicious activity in network traffic logs. It combines
**rule-based detection** (port scans, brute force, blacklisted IPs) with an
**Isolation Forest** machine-learning model that catches deviations from normal traffic,
like volume bursts and unusual packet sizes. Alerts go to `alerts.log` with severity
levels, and a **Rich** terminal dashboard shows traffic stats and a breakdown of the alerts.

There's a built-in **mock data generator**, so you can try the whole pipeline right away
without capturing live traffic or needing root privileges.

---

## ✨ Features

| Capability | Details |
|---|---|
| **Port scan detection** | Alerts when one source hits **more than 10 unique ports** on one host within **5 s** (sliding window). HIGH if 50 or more ports. |
| **Brute-force detection** | Alerts when one source makes **more than 20 connections** to the same auth service (SSH, RDP, FTP, SMB, DBs…) within **10 s**. HIGH if the peak is 40 or more. |
| **Blacklist matching** | Single IPs **and CIDR blocks**. Outbound traffic to a bad host (possible C2) is HIGH. Inbound traffic from one is MEDIUM. |
| **ML anomaly detection** | Isolation Forest trained on packet size plus per-source connection frequency and byte-volume features. Each alert names the feature that deviated most from baseline. |
| **Cross-correlation** | ML alerts whose source was also caught by a rule are tagged `corroborates PORT_SCAN`, etc. |
| **Robust parsing** | Bad timestamps, IPs, ports, protocols, sizes and field counts are rejected with line numbers. The run never crashes on them. |
| **Alert logging** | One pipe-delimited line per alert in `alerts.log`, plus optional JSON export. |
| **Rich dashboard** | Traffic summary, protocol distribution, alerts by severity and type, top talkers, and recent alerts colour-coded by severity. Optional animated **live replay**. |

---

## 🏗️ Architecture

```
                         ┌────────────────────────────┐
   python main.py        │   mock_data_generator.py   │  (--generate)
   ───────────────┐      │  normal traffic + injected │
                  │      │  scans / brute force / ... │
                  │      └─────────────┬──────────────┘
                  │                    │ writes
                  ▼                    ▼
          ┌──────────────┐     data/network_logs.csv
          │   main.py    │             │
          │ orchestrator │             │ reads
          └──────┬───────┘             ▼
                 │            ┌──────────────────┐
                 ├──────────► │  log_parser.py   │  validate, normalise,
                 │            │  ParseResult/df  │  reject malformed rows
                 │            └────────┬─────────┘
                 │                     │ pandas DataFrame
                 │                     ▼
                 │   ┌───────────────────────────────────────────┐
                 ├─► │            detection_engine.py            │
                 │   │  ┌──────────────────┐ ┌─────────────────┐ │
                 │   │  │RuleBasedDetector │ │MLAnomalyDetector│ │
                 │   │  │ • port scan      │ │ Isolation Forest│ │
                 │   │  │ • brute force    │ │ • packet_length │ │
                 │   │  │ • blacklist      │ │ • conn frequency│ │
                 │   │  └────────┬─────────┘ └───────┬─────────┘ │
                 │   │           └──► DetectionEngine ◄┘          │
                 │   │               merge + corroborate          │
                 │   └──────────────────────┬────────────────────┘
                 │                          │ List[Alert]
                 │                          ▼
                 │               ┌─────────────────────┐
                 ├─────────────► │    alerting.py      │ ──► alerts.log
                 │               │ Alert / AlertManager│ ──► alerts.json (opt.)
                 │               └──────────┬──────────┘
                 │                          ▼
                 │               ┌─────────────────────┐
                 └─────────────► │    dashboard.py     │ ──► Rich terminal UI
                                 └─────────────────────┘

                 config.py  ◄── thresholds, blacklist, paths, ML params (used by all)
```

---

## 📁 Project Structure

```
network_anomaly_detector/
├── README.md
├── requirements.txt
├── config.py              # Central configuration (thresholds, blacklists, paths, ML params)
├── mock_data_generator.py # Generates synthetic CSV logs with embedded anomalies
├── log_parser.py          # Parses + validates CSV log files into a DataFrame
├── detection_engine.py    # Rule-based + Isolation Forest ML detection
├── alerting.py            # Alert model, severity levels, alerts.log writer
├── dashboard.py           # Rich terminal dashboard (static + live replay)
├── main.py                # CLI orchestrating the whole pipeline
└── data/                  # Generated / input log files
    └── .gitkeep
```

---

## ⚙️ Installation

Requires **Python 3.10+**.

```bash
cd network_anomaly_detector
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

---

## 🚀 Usage

### Quick start (generate data, detect, show the dashboard)

```bash
python main.py --generate --dashboard
```

### Common commands

```bash
# 1) Generate synthetic logs only (defaults: ~10,000 rows -> data/network_logs.csv)
python mock_data_generator.py
python mock_data_generator.py --rows 20000 --seed 7 --output data/big.csv

# 2) Analyse a log file and print the alert list
python main.py --input data/network_logs.csv

# 3) Show the Rich dashboard
python main.py --dashboard

# 4) Animated "live" replay of the capture
python main.py --dashboard --live

# 5) Rules only (no ML), show only HIGH alerts
python main.py --no-ml --min-severity HIGH

# 6) Also export alerts as JSON (default: data/alerts.json)
python main.py --json
python main.py --json reports/alerts.json

# 7) Tune Isolation Forest sensitivity
python main.py --contamination 0.02
```

### CLI reference (`python main.py --help`)

| Option | Description | Default |
|---|---|---|
| `-i, --input PATH` | CSV log file to analyse | `data/network_logs.csv` |
| `-g, --generate` | Generate synthetic logs to `--input` first | off |
| `--rows N` / `--seed N` | Size / seed of the generated data | `10000` / `1337` |
| `-d, --dashboard` | Show the Rich dashboard | off |
| `--live` | Animated replay dashboard (implies `--dashboard`) | off |
| `-a, --alerts-log PATH` | Alert log file | `alerts.log` |
| `--append` | Append to the alert log instead of overwriting | off |
| `--json [PATH]` | Export alerts as JSON | off |
| `--no-ml` | Disable Isolation Forest | off |
| `--contamination F` | Expected anomaly ratio (0 < F ≤ 0.5) | `0.03` |
| `--min-severity` | Minimum severity in the console list | `LOW` |
| `-q, --quiet` | Don't print the alert list | off |

Exit codes: `0` success, `1` input/parse error, `2` invalid arguments.

---

## 📄 Log Format

CSV with a header row. Each row is one connection/flow record:

```csv
Timestamp,Source IP,Destination IP,Source Port,Destination Port,Protocol,Packet Length
2026-10-05 08:12:00.000000,203.0.113.45,192.168.1.10,51514,22,TCP,52
```

* **Timestamp**: any format pandas can parse (ISO 8601 recommended).
* **IPs**: IPv4 or IPv6.
* **Ports**: integers 0–65535 (use `0` for ICMP).
* **Protocol**: `TCP`, `UDP` or `ICMP` (case-insensitive).
* **Packet Length**: 1–65535 bytes.

Headers are matched case-insensitively. Snake_case headers (`timestamp, src_ip, …`) also work.

---

## 🚨 Alert Output

Each line in `alerts.log` has this format:

```
[detected-at] event-time | SEVERITY | TYPE | source -> destination | description | {json details}
```

Example:

```
[2026-10-05 14:02:11] 2026-10-05 08:12:00.000 | HIGH   | PORT_SCAN      | 203.0.113.45 -> 192.168.1.10 | Port scan: 64 unique ports probed in 3.0s (threshold >10 in 5s) | {"events": 64, "unique_ports": 64, ...}
[2026-10-05 14:02:11] 2026-10-05 08:24:00.000 | HIGH   | BRUTE_FORCE    | 198.51.100.23 -> 192.168.1.20 | Brute force on port 22: 60 connections in 14.7s (peak 41 in 10s, threshold >20) | {...}
[2026-10-05 14:02:11] 2026-10-05 08:00:03.160 | HIGH   | BLACKLISTED_IP | 10.0.0.18 -> 192.0.2.99 | Outbound connections to blacklisted host 192.0.2.99: 20 events, ... | {...}
```

### Severity rules

| Type | LOW | MEDIUM | HIGH |
|---|---|---|---|
| `PORT_SCAN` | – | more than 10 ports in 5 s | 50 or more unique ports |
| `BRUTE_FORCE` | – | more than 20 connections in 10 s | in-window peak of 40 or more |
| `BLACKLISTED_IP` | – | inbound from a bad host | outbound to a bad host |
| `ML_ANOMALY` | score > −0.05 | −0.15 < score ≤ −0.05 | score ≤ −0.15 |

All thresholds can be changed in `config.py`.

---

## 🧩 Module Descriptions

### `config.py`
Frozen dataclasses (`PathConfig`, `SchemaConfig`, `RuleConfig`, `MLConfig`,
`DashboardConfig`, `GeneratorConfig`) grouped into one `AppConfig` instance called `CONFIG`.
To customise it without editing the file, use `dataclasses.replace`:

```python
from dataclasses import replace
from config import CONFIG
cfg = replace(CONFIG, rules=replace(CONFIG.rules, port_scan_unique_ports=5))
```

### `mock_data_generator.py`
`MockDataGenerator` writes about 10k rows of realistic background traffic (ports
80/443/22/53/8080, TCP/UDP/ICMP, packet sizes 64–1500) and injects these scenarios:

| Scenario | Rows | Expected detection |
|---|---|---|
| Fast port scan (64 ports in ~3 s) | 64 | PORT_SCAN HIGH + ML |
| Small port scan (14 ports in ~4 s) | 14 | PORT_SCAN MEDIUM + ML |
| SSH brute force (60 conns in ~15 s) | 60 | BRUTE_FORCE HIGH + ML |
| RDP brute force (25 conns in ~8 s) | 25 | BRUTE_FORCE MEDIUM + ML |
| Blacklisted inbound + C2 beaconing | 50 | BLACKLISTED_IP |
| Jumbo packets (> 9000 B) | 25 | ML_ANOMALY |
| HTTPS exfiltration burst | 120 | ML_ANOMALY only (no rule covers it) |
| Malformed rows | 7 | Rejected by the parser |

### `log_parser.py`
`LogParser.parse()` reads the file with the `csv` module. Rows with the wrong number of
fields are recorded and skipped. It then normalises headers, validates every field with
vectorised pandas checks, and returns a `ParseResult` with:
* `data`: a typed DataFrame sorted by timestamp
* stats: `total_rows`, `valid_rows`, `invalid_rows`
* `errors`: a list of `RowError(line_number, reason, raw)`

`ParseResult.to_records()` gives you the rows as a list of dicts.

### `detection_engine.py`
* **`sliding_window_incidents()`**: a two-pointer sliding window over sorted timestamps.
  It counts events or distinct values, and merges consecutive violating windows so that
  one attack produces one alert.
* **`RuleBasedDetector`**: `detect_port_scans()`, `detect_brute_force()` and
  `detect_blacklisted()`. A cheap group-level pre-filter keeps these fast.
* **`MLAnomalyDetector`**: `build_features()` computes trailing 10-second windows using
  `searchsorted` and cumulative sums. It also has `fit()`, `predict()` (adds
  `anomaly_score` and `is_anomaly`) and `detect()`, which groups anomalous records into
  per src→dst alerts with an explanation.
* **`DetectionEngine`**: runs both detectors, tags ML alerts that corroborate a rule,
  records timings and warnings, and returns a `DetectionResult`.

### `alerting.py`
`Severity` and `AlertType` enums, plus a frozen `Alert` dataclass (`timestamp`,
`alert_type`, `severity`, `source_ip`, `dest_ip`, `description`, `details`).
`AlertManager` writes to `alerts.log` through a dedicated logger and keeps the alerts in
memory. It provides `filter()`, `count_by_severity()`, `count_by_type()`, `recent()` and
`export_json()`.

### `dashboard.py`
`Dashboard.build()` puts together the summary, alert breakdown, top talkers and recent
alerts panels. `render()` prints a snapshot. `live_replay()` steps through the capture in
time slices inside `rich.live.Live`.

### `main.py`
The argparse CLI that runs the pipeline: generate → parse → detect → log → display.

---

## 🧠 How the ML Detector Works

For each record, the model looks at four features:

| Feature | Meaning |
|---|---|
| `packet_length` | Bytes in the record |
| `src_conn_freq` | Records from the same source in the previous 10 s |
| `src_bytes_window` | Bytes from the same source in the previous 10 s |
| `pair_conn_freq` | Records for the same src→dst pair in the previous 10 s |

The Isolation Forest isolates points with random splits. Points that are easy to isolate
are rare, so they get low scores and are flagged. `contamination` (default **0.03**) sets
the share of records treated as anomalous. The default is tuned to the synthetic data,
where about 3% of rows are injected anomalies. For real traffic, start lower (for example
`0.005`–`0.01`) and adjust based on how many false positives you see.

On the bundled data set, the model flags the scans, brute-force bursts, exfiltration burst
and all jumbo packets. It also raises a few LOW-severity alerts for slightly busy hosts.
Expect some false positives like these from any unsupervised model.

---

## 🔧 Extending

* **New rule**: add a `detect_*` method to `RuleBasedDetector`, call it from `detect()`,
  and add an `AlertType` member.
* **New ML feature**: compute it in `MLAnomalyDetector.build_features()` and add its name
  to `MLConfig.feature_columns`.
* **Live capture**: convert packets (from scapy, tshark or Zeek) into the same CSV/DataFrame
  schema and pass them to `DetectionEngine.run()`.

---

## ⚠️ Disclaimer

This is an educational / demo tool. The blacklist uses RFC 5737 documentation ranges
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), so no real host is implicated.
Only analyse traffic you are authorised to monitor.
