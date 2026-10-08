# 🛡️ Network Log & Anomaly Detector

A modular Python tool for spotting suspicious activity in network traffic logs. It combines\
**rule-based detection** (port scans, brute force, blacklisted IPs) with an\
**Isolation Forest** machine-learning model that catches deviations from normal traffic,\
like volume bursts and unusual packet sizes. Alerts go to `alerts.log` with severity\
levels, and a **Rich** terminal dashboard shows traffic stats and a breakdown of the alerts.

There's a built-in **mock data generator**, so you can try the whole pipeline right away\
without capturing live traffic or needing root privileges.

**Version 2.0** adds detectors for **DNS tunneling**, **C2 beaconing** and **off-hours activity**,\
live **threat-intelligence feeds**, direct **.pcap / .pcapng** input, **streaming** for very large\
files, a self-contained **HTML report**, a **Streamlit** web dashboard and a **pytest** test suite.\
See [What's new in V2](#-whats-new-in-v2) and the [Changelog](#-changelog).

---

## ✨ Features

| Capability | Details |
| --- | --- |
| **Port scan detection** | Alerts when one source hits **more than 10 unique ports** on one host within **5 s** (sliding window). HIGH if 50 or more ports. |
| **Brute-force detection** | Alerts when one source makes **more than 20 connections** to the same auth service (SSH, RDP, FTP, SMB, DBs…) within **10 s**. HIGH if the peak is 40 or more. |
| **Blacklist matching** | Single IPs **and CIDR blocks**. Outbound traffic to a bad host (possible C2) is HIGH. Inbound traffic from one is MEDIUM. |
| **ML anomaly detection** | Isolation Forest trained on packet size plus per-source connection frequency and byte-volume features. Each alert names the feature that deviated most from baseline. |
| **Cross-correlation** | ML alerts whose source was also caught by a rule are tagged `corroborates PORT_SCAN`, etc. |
| **Robust parsing** | Bad timestamps, IPs, ports, protocols, sizes and field counts are rejected with line numbers. The run never crashes on them. |
| **Public dataset support** | Reads **CICIDS2017**, **CSE-CIC-IDS2018** and **UNSW-NB15** CSVs directly. The format is auto-detected, columns are mapped, and protocol numbers are turned into names. You can also supply your own column mapping. See [Using External Datasets](#-using-external-datasets). |
| **Alert logging** | One pipe-delimited line per alert in `alerts.log`, plus optional JSON export. |
| **Rich dashboard** | Traffic summary, protocol distribution, alerts by severity and type, top talkers, and recent alerts colour-coded by severity. Optional animated **live replay**. |
| **DNS tunneling detection** (V2) | Alerts when one source sends **more than 50 DNS queries** (port 53) within **60 s**. HIGH if the peak is above 100. |
| **C2 beaconing detection** (V2) | Alerts when a source contacts the same host **more than 10 times** at near-regular intervals (gap spread **under 2 s**, average gap at least 5 s). HIGH if the spread is under 0.5 s over 20+ connections. |
| **Off-hours activity** (V2) | Alerts when one source makes **more than 100 connections** outside business hours (default 22:00–06:00). HIGH above 500. |
| **Threat-intelligence feeds** (V2) | Downloads public IP blocklists (Emerging Threats, abuse.ch Feodo Tracker), caches them for 24 h, and merges them with the static blacklist. Matches become `THREAT_INTEL_HIT` alerts. Works offline from the cache, or falls back to the static blacklist. |
| **PCAP input** (V2) | Reads `.pcap`, `.pcapng` and `.cap` captures directly (via `dpkt`), IPv4 and IPv6, over Ethernet, Linux "cooked" capture, loopback or raw IP. Unreadable packets are skipped and counted. |
| **Streaming mode** (V2) | `--chunk-size N` processes huge CSV files in chunks with overlapping windows, so memory use stays flat. Rule and V2 alerts match a normal run. ML alerts match for files up to 20,000 rows and can differ slightly above that. |
| **HTML report** (V2) | One self-contained file (inline CSS and SVG charts, no internet needed): executive summary, alert timeline, protocol pie, top talkers, detection-method breakdown and the full alert table. |
| **Streamlit web dashboard** (V2) | Upload a CSV or pcap, filter by severity / type / time / text, interactive Plotly charts, and CSV / JSON / HTML report downloads. |
| **Test suite** (V2) | 66 pytest tests covering parsing, every detector, alerting, threat intel, PCAP, streaming and the report. Runs offline in a few seconds. |

---

## 🆕 What's new in V2

In plain terms, V2 helps the tool catch three kinds of sneaky behaviour that V1 missed, and\
gives you more ways to feed data in and see the results.

| New in V2 | What it's for | How to use it |
| --- | --- | --- |
| **DNS tunneling detector** | Spots a machine hiding data inside a flood of DNS lookups | On by default |
| **Beaconing detector** | Spots malware "phoning home" to its controller on a regular timer | On by default |
| **Off-hours detector** | Spots a machine that is unusually busy at night | On by default |
| **Threat-intelligence feeds** | Checks traffic against public lists of known-bad IPs, updated daily | On by default. `--update-feeds` to refresh now, `--no-threat-intel` to turn off |
| **PCAP input** | Analyse Wireshark / tcpdump captures directly | `--input capture.pcap` |
| **Streaming** | Analyse files too big to fit in memory | `--chunk-size 50000` |
| **HTML report** | A shareable report you can open in any browser or e-mail | `--report` |
| **Web dashboard** | Point-and-click dashboard with filters and charts | `--streamlit` |
| **Test suite** | Confirms everything still works after a change | `python3 -m pytest -q` |

Use `--no-v2` to turn off the three new detectors and get V1 behaviour.

On the bundled sample data (`python3 main.py --generate`), V2 finds 1 DNS tunneling alert (HIGH),\
1 beaconing alert (HIGH) and 1 off-hours alert (MEDIUM). Because the sample data is made up,\
none of its addresses appear in the real threat feeds, so it produces no threat-intel hits.

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

#### V2 additions

```
  .pcap / .pcapng ──► pcap_parser.py ──┐
  .csv ─────────────► log_parser.py ───┼──► DataFrame ──► DetectionEngine
  huge .csv ────────► streaming.py ────┘    (chunked)       │  rules + ML (V1)
                     (--chunk-size N)                       │  + DNSTunnelingDetector
                                                            │  + BeaconingDetector
  threat_intel.py ──► extra blocklist entries ──────────────┤  + TimeOfDayDetector
  (download → cache → static fallback)                      │  + THREAT_INTEL_HIT
                                                            ▼
                         alerting.py ──► alerts.log / alerts.json
                         dashboard.py ──► Rich terminal UI (with V2 panel)
                         report_generator.py + templates/report.html ──► report.html
                         streamlit_app.py ──► web dashboard (browser)
```

Every V2 step is optional. If a V2 module fails (for example, no internet for the feeds),\
the run prints a warning and the V1 pipeline still completes.

---

## 📁 Project Structure

```
network_anomaly_detector/
├── README.md
├── requirements.txt
├── config.py              # Central configuration (thresholds, blacklists, paths, ML params)
├── mock_data_generator.py # Generates synthetic CSV logs with embedded anomalies
├── log_parser.py          # Parses + validates CSV logs (native, CICIDS, UNSW-NB15, custom)
├── detection_engine.py    # Rule-based + Isolation Forest ML detection
├── alerting.py            # Alert model, severity levels, alerts.log writer
├── dashboard.py           # Rich terminal dashboard (static + live replay)
├── main.py                # CLI orchestrating the whole pipeline
├── threat_intel.py        # (V2) Threat-feed download, caching and parsing
├── pcap_parser.py         # (V2) .pcap / .pcapng → DataFrame
├── streaming.py           # (V2) Chunked processing for very large CSV files
├── report_generator.py    # (V2) Self-contained HTML report
├── streamlit_app.py       # (V2) Streamlit web dashboard
├── templates/
│   └── report.html        # (V2) Jinja2 template for the HTML report
├── tests/                 # (V2) pytest suite (conftest.py + 7 test modules)
└── data/                  # Generated / input log files
    └── .gitkeep
```

---

## ⚙️ Installation

Requires **Python 3.10+**.

> **⚠️ Important — `python3` vs `python`**
>
> On **macOS / Linux**, the system Python 2 may still be at `python`, so always use\
> **`python3`** and **`pip3`** (or run inside an activated virtual environment).\
> On **Windows**, the Python 3 installer registers itself as **`python`** and **`pip`**\
> by default.
>
> Every command below is shown in **both** forms. Pick the one that matches your OS\
> and use it consistently.

**macOS / Linux (Terminal)**

```bash
cd network_anomaly_detector
python3 -m venv .venv
source .venv/bin/activate
pip3 install -r requirements.txt
```

**Windows (Command Prompt / PowerShell)**

```cmd
cd network_anomaly_detector
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

---

## 🚀 Usage

### Quick start (generate data, detect, show the dashboard)

**macOS / Linux**

```bash
python3 main.py --generate --dashboard
```

**Windows**

```cmd
python main.py --generate --dashboard
```

### Common commands

> Shown with `python3` (macOS/Linux). On **Windows**, replace `python3` with `python`.

```bash
# 1) Generate synthetic logs only (defaults: ~10,000 rows -> data/network_logs.csv)
python3 mock_data_generator.py
python3 mock_data_generator.py --rows 20000 --seed 7 --output data/big.csv

# 2) Analyse a log file and print the alert list
python3 main.py --input data/network_logs.csv

# 3) Show the Rich dashboard
python3 main.py --dashboard

# 4) Animated "live" replay of the capture
python3 main.py --dashboard --live

# 5) Rules only (no ML), show only HIGH alerts
python3 main.py --no-ml --min-severity HIGH

# 6) Also export alerts as JSON (default: data/alerts.json)
python3 main.py --json
python3 main.py --json reports/alerts.json

# 7) Tune Isolation Forest sensitivity
python3 main.py --contamination 0.02

# 8) Analyse a public dataset (format auto-detected; see "Using External Datasets")
python3 main.py --input data/Tuesday-WorkingHours.pcap_ISCX.csv --dashboard
python3 main.py --input data/UNSW-NB15_1.csv --profile unsw
```

### V2 commands

> Shown with `python3` (macOS/Linux). On **Windows**, replace `python3` with `python`.

```bash
# 9) Analyse a packet capture directly (.pcap / .pcapng / .cap)
python3 main.py --input capture.pcap --dashboard

# 10) Write a self-contained HTML report (default: data/report.html)
python3 main.py --report
python3 main.py --report reports/october.html

# 11) Stream a very large CSV in chunks of 50,000 rows (flat memory use)
python3 main.py --input data/huge.csv --chunk-size 50000

# 12) Refresh the threat-intelligence feeds now (otherwise refreshed every 24 h)
python3 main.py --update-feeds

# 13) Work fully offline: static blacklist only, no feed download
python3 main.py --no-threat-intel

# 14) V1 behaviour only (no DNS / beaconing / off-hours detectors)
python3 main.py --no-v2

# 15) Open the Streamlit web dashboard in your browser
python3 main.py --streamlit
# (same as: streamlit run streamlit_app.py)
```

### CLI reference (`python3 main.py --help` / `python main.py --help`)

| Option | Description | Default |
| --- | --- | --- |
| `--version` | Print the version (`2.0.0`) and exit | – |
| `-i, --input PATH` | CSV log file or `.pcap` / `.pcapng` capture to analyse | `data/network_logs.csv` |
| `-p, --profile NAME` | Input format: `auto`, `cicids`, `unsw` or `default` (native). Ignored for pcap files | `auto` |
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
| `--report [PATH]` | (V2) Write a self-contained HTML report | off (`data/report.html` if no path) |
| `--chunk-size N` | (V2) Stream CSV input in chunks of N rows | off |
| `--no-v2` | (V2) Disable the DNS tunneling, beaconing and off-hours detectors | off |
| `--update-feeds` | (V2) Force a fresh download of the threat-intelligence feeds | off |
| `--no-threat-intel` | (V2) Don't load threat feeds (static blacklist only) | off |
| `--streamlit` | (V2) Launch the Streamlit web dashboard instead of the CLI pipeline | off |

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

**Packet captures (V2):** `.pcap`, `.pcapng` and `.cap` files don't need any conversion.\
Each TCP, UDP or ICMP packet becomes one row with the same seven columns. Packets that\
aren't IP (ARP, for example) or can't be decoded are skipped and counted in the summary.

---

## 🌐 Using External Datasets

Besides its own format, the tool can read well-known public intrusion-detection datasets\
**as downloaded**. You don't need to rename columns or convert anything first.

### Download links

| Dataset | Publisher | Link |
| --- | --- | --- |
| **CICIDS2017** | Canadian Institute for Cybersecurity (UNB) | [https://www.unb.ca/cic/datasets/ids-2017.html](https://www.unb.ca/cic/datasets/ids-2017.html) |
| **CSE-CIC-IDS2018** | CSE & Canadian Institute for Cybersecurity (on AWS) | [https://www.unb.ca/cic/datasets/ids-2018.html](https://www.unb.ca/cic/datasets/ids-2018.html) |
| **UNSW-NB15** | UNSW Canberra Cyber | [https://research.unsw.edu.au/projects/unsw-nb15-dataset](https://research.unsw.edu.au/projects/unsw-nb15-dataset) |

For CICIDS2017, use the _flow_ CSVs (`GeneratedLabelledFlows` / `TrafficLabelling`), not the\
`MachineLearningCVE` CSVs. The `MachineLearningCVE` files have no IP or timestamp columns,\
so the detector cannot work with them. For UNSW-NB15, use `UNSW-NB15_1.csv` … `UNSW-NB15_4.csv`.\
The `*_training-set.csv` / `*_testing-set.csv` files have no IPs or timestamps.

### Dataset profiles

A **profile** tells the parser which column in the file holds which piece of information.

| Profile | Use it for | Timestamp | Source IP | Destination IP | Source port | Destination port | Protocol | Packet length |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `default` | This tool's native format | `Timestamp` | `Source IP` | `Destination IP` | `Source Port` | `Destination Port` | `Protocol` | `Packet Length` |
| `cicids` | CICIDS2017 | ` Timestamp` | ` Source IP` | ` Destination IP` | ` Source Port` | ` Destination Port` | ` Protocol` | `Total Length of Fwd Packets` |
| `cicids` | CSE-CIC-IDS2018 | `Timestamp` | `Src IP` | `Dst IP` | `Src Port` | `Dst Port` | `Protocol` | `TotLen Fwd Pkts` |
| `unsw` | UNSW-NB15 | `stime` | `srcip` | `dstip` | `sport` | `dsport` | `proto` | `sbytes` |

The mappings are defined in `COLUMN_MAPPING` in `config.py`.

What the parser does for you:

* **Strips whitespace** from column names. CICIDS2017 headers start with a space (`" Source IP"`).\
  Names are also matched case-insensitively, and a byte-order mark is ignored.

* **Converts numeric protocols to names** using `PROTOCOL_NUMBER_MAP` in `config.py`\
  (`6`→`TCP`, `17`→`UDP`, `1`→`ICMP`, `0`→`HOPOPT`, `2`→`IGMP`, `47`→`GRE`, `89`→`OSPF`, …).\
  Numbers that aren't in the map become `PROTO-<n>`.

* **Reads each dataset's timestamps correctly.** CICIDS uses day/month/year (`3/7/2017 8:55` = 3 July 2017).\
  UNSW-NB15 uses Unix epoch seconds.

* **Handles dataset quirks:**

  * The UNSW-NB15 CSV files have no header row. The parser recognises them by their 49 columns and fills in the official column names.

  * In UNSW-NB15, ports written as `-` are read as 0, and hexadecimal ports (`0x000b`) are converted.

  * In CSE-CIC-IDS2018, header rows that repeat in the middle of a file are skipped.

  * Protocols other than TCP/UDP/ICMP (e.g. `HOPOPT`, `ARP`, `OSPF`) are accepted for external datasets.

* **Shows which mapping was used.** It logs it, and the CLI prints it:

  ```
  ✔ Dataset profile: cicids — CICIDS2017 / CSE-CIC-IDS2018 (CICFlowMeter flows) (auto-detected)
    column mapping: 'Timestamp'→timestamp, 'Source IP'→src_ip, ..., 'Total Length of Fwd Packets'→packet_length
  ```

### Auto-detection

`--profile auto` is the default. It works like this:

1. If the first row looks like data rather than a header (it starts with an IP address and has 49 fields),\
  the file is treated as a **headerless UNSW-NB15** file.

2. Otherwise, the parser checks each profile against the header. It picks the one that matches all\
  7 required fields. If more than one matches, it picks the one with the most dataset-specific columns\
  (e.g. `Flow ID` / `Flow Duration` for CICIDS, `dbytes` / `ltime` for UNSW).

3. If no profile matches, the run stops with exit code `1` and a message listing the missing columns.

### Choosing a profile with `--profile`

> Shown with `python3` (macOS/Linux). On **Windows**, replace `python3` with `python`.

```bash
# Let the tool work out the format (default)
python3 main.py -i data/Wednesday-workingHours.pcap_ISCX.csv

# Force a specific profile (useful if auto-detection guesses wrong)
python3 main.py -i data/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv --profile cicids
python3 main.py -i data/UNSW-NB15_3.csv --profile unsw --dashboard

# Force the native format
python3 main.py -i data/network_logs.csv --profile default
```

If you force a profile that doesn't fit the file, the error tells you which columns are\
missing and what names were expected.

### Custom mappings (Python API)

For any other CSV, give the parser a dict that maps **your column names** to the canonical\
names: `timestamp`, `source_ip`, `destination_ip`, `source_port`, `destination_port`,\
`protocol` and `packet_length`. The internal names `src_ip` / `dst_ip` / `src_port` /\
`dst_port` work too.

```python
from config import CONFIG
from log_parser import parse_log_file

mapping = {"ts": "timestamp", "from": "source_ip", "to": "destination_ip",
           "fport": "source_port", "tport": "destination_port",
           "proto_num": "protocol", "bytes": "packet_length"}

result = parse_log_file("my_firewall.csv", CONFIG, dataset_profile=mapping)
# or: parse_log_file(path, CONFIG, dataset_profile="custom", column_mapping=mapping)
print(result.profile, result.valid_rows, result.column_mapping)
```

In the Python API, `dataset_profile=None` (the default) means the native format, so existing code\
works exactly as before. Pass `"auto"` to turn on detection.

### Things to keep in mind

* **These datasets contain flows, not packets.** One row is a whole connection.\
  `packet_length` is filled with the bytes sent by the source (`Total Length of Fwd Packets` / `sbytes`),\
  so values can be much larger than 1,500 and can be 0. The ML model treats those values as normal for the\
  file it is analysing. The rule thresholds in `config.py` (ports per 5 s, connections per 10 s) were\
  designed for packet-level logs. You may want to tune them for flow data.

* **The label columns are ignored.** `Label` and `attack_cat` are not used for detection. You can\
  use them yourself to check the alerts afterwards.

* **Memory.** Single CICIDS / UNSW files hold hundreds of thousands to millions of rows, and\
  the parser loads the whole file into memory. Start with one day's file, or use\
  `--chunk-size` (V2) to stream it in pieces.

* Rows with `Infinity` / `NaN` in _unused_ columns (common in CICIDS) are fine. Only the 7 mapped\
  columns are checked.

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
| --- | --- | --- | --- |
| `PORT_SCAN` | – | more than 10 ports in 5 s | 50 or more unique ports |
| `BRUTE_FORCE` | – | more than 20 connections in 10 s | in-window peak of 40 or more |
| `BLACKLISTED_IP` | – | inbound from a bad host | outbound to a bad host |
| `ML_ANOMALY` | score > −0.05 | −0.15 < score ≤ −0.05 | score ≤ −0.15 |
| `DNS_TUNNELING` (V2) | – | more than 50 DNS queries in 60 s | in-window peak above 100 |
| `BEACONING` (V2) | – | more than 10 regular connections (gap spread < 2 s) | spread < 0.5 s and 20+ connections |
| `TIME_OF_DAY_ANOMALY` (V2) | – | more than 100 off-hours connections | more than 500 |
| `THREAT_INTEL_HIT` (V2) | – | inbound from a feed-listed host | outbound to a feed-listed host |

All thresholds can be changed in `config.py` (`RuleConfig`, `MLConfig`, and for V2 `DNSConfig`,\
`BeaconingConfig`, `TimeOfDayConfig` and `ThreatFeedConfig`).

---

## 🧩 Module Descriptions

### `config.py`

Frozen dataclasses (`PathConfig`, `SchemaConfig`, `RuleConfig`, `MLConfig`,\
`DashboardConfig`, `GeneratorConfig`, and in V2 `DNSConfig`, `BeaconingConfig`, `TimeOfDayConfig`,\
`ThreatFeedConfig`, `PcapConfig`, `StreamingConfig`, `ReportConfig`) grouped into one `AppConfig`\
instance called `CONFIG`. `__version__` holds the version number (`2.0.0`).\
The dataset-ingestion settings live in this file too:

* `COLUMN_MAPPING`: presets `cicids`, `unsw` and `custom`

* `PROTOCOL_NUMBER_MAP`

* `UNSW_NB15_COLUMNS`

* `DATASET_PROFILES`

* `make_custom_profile()`

To customise it without editing the file, use `dataclasses.replace`:

```python
from dataclasses import replace
from config import CONFIG
cfg = replace(CONFIG, rules=replace(CONFIG.rules, port_scan_unique_ports=5))
```

### `mock_data_generator.py`

`MockDataGenerator` writes about 10k rows of realistic background traffic (ports\
80/443/22/53/8080, TCP/UDP/ICMP, packet sizes 64–1500) and injects these scenarios:

| Scenario | Rows | Expected detection |
| --- | --- | --- |
| Fast port scan (64 ports in \~3 s) | 64 | PORT_SCAN HIGH + ML |
| Small port scan (14 ports in \~4 s) | 14 | PORT_SCAN MEDIUM + ML |
| SSH brute force (60 conns in \~15 s) | 60 | BRUTE_FORCE HIGH + ML |
| RDP brute force (25 conns in \~8 s) | 25 | BRUTE_FORCE MEDIUM + ML |
| Blacklisted inbound + C2 beaconing | 50 | BLACKLISTED_IP |
| Jumbo packets (> 9000 B) | 25 | ML_ANOMALY |
| HTTPS exfiltration burst | 120 | ML_ANOMALY only (no rule covers it) |
| Malformed rows | 7 | Rejected by the parser |
| DNS tunneling (\~130 queries in \~55 s) (V2) | \~130 | DNS_TUNNELING HIGH |
| C2 beaconing (every 30 s ± 0.2 s, 40 conns) (V2) | 40 | BEACONING HIGH |
| Off-hours burst (\~150 conns, 04:30–05:30) (V2) | \~150 | TIME_OF_DAY_ANOMALY MEDIUM |

The V2 scenarios use their own random stream, so for a given seed the V1 scenarios are\
generated exactly as before.

### `log_parser.py`

`LogParser(config, dataset_profile=None, column_mapping=None).parse()` reads the file with the\
`csv` module and picks a dataset profile (`"auto"`, `"cicids"`, `"unsw"`, `"default"`/`None`,\
`"custom"` or a mapping dict). It then maps the columns onto the internal schema, keeping only the\
7 needed fields. Rows with the wrong number of fields (and repeated header rows) are recorded and\
skipped. Protocol numbers are converted to names, and every field is validated with vectorised\
pandas checks. It returns a `ParseResult` with:

* `data`: a typed DataFrame sorted by timestamp

* stats: `total_rows`, `valid_rows`, `invalid_rows`

* `errors`: a list of `RowError(line_number, reason, raw)`

* `profile`, `auto_detected`, `headerless`, `column_mapping`: which mapping was used

`ParseResult.to_records()` gives you the rows as a list of dicts.

### `detection_engine.py`

* **`sliding_window_incidents()`**: a two-pointer sliding window over sorted timestamps.\
  It counts events or distinct values, and merges consecutive violating windows so that\
  one attack produces one alert.

* **`RuleBasedDetector`**: `detect_port_scans()`, `detect_brute_force()` and\
  `detect_blacklisted()`. A cheap group-level pre-filter keeps these fast.

* **`MLAnomalyDetector`**: `build_features()` computes trailing 10-second windows using\
  `searchsorted` and cumulative sums. It also has `fit()`, `predict()` (adds\
  `anomaly_score` and `is_anomaly`) and `detect()`, which groups anomalous records into\
  per src→dst alerts with an explanation.

* **`DNSTunnelingDetector`** (V2): sliding window over DNS queries per source.

* **`BeaconingDetector`** (V2): measures the gaps between connections for each src→dst pair\
  and flags timer-like regularity.

* **`TimeOfDayDetector`** (V2): counts each source's connections outside business hours.

* **`DetectionEngine`**: runs both detectors, tags ML alerts that corroborate a rule,\
  records timings and warnings, and returns a `DetectionResult`. In V2 it also runs the\
  three new detectors (`run_v2_detectors()`). Each one is isolated, so an error there\
  becomes a warning and never affects the V1 results.

### `alerting.py`

`Severity` and `AlertType` enums, plus a frozen `Alert` dataclass (`timestamp`,\
`alert_type`, `severity`, `source_ip`, `dest_ip`, `description`, `details`).\
`AlertManager` writes to `alerts.log` through a dedicated logger and keeps the alerts in\
memory. It provides `filter()`, `count_by_severity()`, `count_by_type()`, `recent()` and\
`export_json()`.

### `dashboard.py`

`Dashboard.build()` puts together the summary, alert breakdown, top talkers and recent\
alerts panels. `render()` prints a snapshot. `live_replay()` steps through the capture in\
time slices inside `rich.live.Live`.

### `main.py`

The argparse CLI that runs the pipeline: generate → parse → detect → log → display.\
In V2 it also picks the PCAP or streaming path, loads threat intel, writes the HTML\
report and can launch the Streamlit app. Each V2 step is wrapped so that a failure\
becomes a warning instead of stopping the run.

### `threat_intel.py` (V2)

`ThreatIntelManager.load()` gets each feed in this order: fresh download → cached copy\
(`data/threat_feeds/`) → nothing (static blacklist only). `parse_feed()` accepts one IP or\
CIDR per line and ignores comments and junk lines. The entries are handed to\
`RuleBasedDetector.add_threat_intel()`.

### `pcap_parser.py` (V2)

`PcapParser(config).parse(path)` reads pcap and pcapng files with `dpkt` and returns the\
same `ParseResult` as `log_parser.py`, so the rest of the pipeline doesn't care where the\
data came from. `is_pcap_file()` recognises captures by extension or by their magic bytes.

### `streaming.py` (V2)

`StreamingProcessor` reads a CSV in chunks. Port-scan, brute-force and DNS rules run on\
each chunk plus an overlap from the previous one, so attacks that cross a chunk boundary\
are still caught. Blacklist/threat-intel, beaconing and off-hours detection collect a small\
summary of every chunk and run once at the end, so they match a normal run. The ML model is\
trained on the first 20,000 rows (`StreamingConfig.ml_warmup_rows`) and later chunks are only\
scored, so on files bigger than that its results can differ slightly from a normal run.\
`deduplicate_alerts()` removes the repeats caused by the overlap.

### `report_generator.py` + `templates/report.html` (V2)

`HTMLReportGenerator().write(path, df, alerts, source=...)` renders the Jinja2 template.\
All charts are inline SVG built in Python, so the report opens offline and can be e-mailed.

### `streamlit_app.py` (V2)

Browser dashboard built on the same modules. It reads data, but never touches the\
CLI's `alerts.log`.

---

## 🧠 How the ML Detector Works

For each record, the model looks at four features:

| Feature | Meaning |
| --- | --- |
| `packet_length` | Bytes in the record |
| `src_conn_freq` | Records from the same source in the previous 10 s |
| `src_bytes_window` | Bytes from the same source in the previous 10 s |
| `pair_conn_freq` | Records for the same src→dst pair in the previous 10 s |

The Isolation Forest isolates points with random splits. Points that are easy to isolate\
are rare, so they get low scores and are flagged. `contamination` (default **0.03**) sets\
the share of records treated as anomalous. The default is tuned to the synthetic data,\
where about 3% of rows are injected anomalies. For real traffic, start lower (for example\
`0.005`–`0.01`) and adjust based on how many false positives you see.

On the bundled data set, the model flags the scans, brute-force bursts, exfiltration burst\
and all jumbo packets. It also raises a few LOW-severity alerts for slightly busy hosts.\
Expect some false positives like these from any unsupervised model.

---

## 🔧 Extending

* **New rule**: add a `detect_*` method to `RuleBasedDetector`, call it from `detect()`,\
  and add an `AlertType` member.

* **New ML feature**: compute it in `MLAnomalyDetector.build_features()` and add its name\
  to `MLConfig.feature_columns`.

* **Live capture**: save packets to a `.pcap` (e.g. with tcpdump or Wireshark) and pass it with\
  `--input`, or convert them (from scapy, tshark or Zeek) into the same CSV/DataFrame schema\
  and pass them to `DetectionEngine.run()`.

* **New V2-style detector**: add a class with a `detect(df) -> List[Alert]` method in\
  `detection_engine.py`, a config dataclass in `config.py`, and call it from\
  `DetectionEngine.run_v2_detectors()`. Add a test in `tests/test_detection.py`.

* **More threat feeds**: add `(name, URL)` pairs to `ThreatFeedConfig.feed_urls`, or local\
  files to `ThreatFeedConfig.local_feed_files`.

---

## ✅ Running Tests

The `tests/` folder holds a **pytest** suite (66 tests). It uses small, made-up data written\
inside the tests, needs no internet, and finishes in a few seconds.

**macOS / Linux**

```bash
python3 -m pytest -q
```

**Windows**

```cmd
python -m pytest -q
```

| File | What it checks |
| --- | --- |
| `tests/test_parser.py` | CSV parsing, validation, rejected rows, dataset profiles |
| `tests/test_detection.py` | Port scan, brute force, blacklist, ML, DNS tunneling, beaconing, off-hours, correlation |
| `tests/test_alerting.py` | Alert log format, filtering, counts, JSON export |
| `tests/test_threat_intel.py` | Feed parsing, caching, offline fallback (network calls are faked) |
| `tests/test_pcap.py` | pcap and pcapng parsing, skipped packets (skipped if `dpkt` isn't installed) |
| `tests/test_streaming.py` | Chunked results match a normal run, de-duplication across chunk overlaps |
| `tests/test_report.py` | HTML report renders, is self-contained, and escapes untrusted text |

---

## 📜 Changelog

### 2.0.0

**Added**

* `DNSTunnelingDetector`, `BeaconingDetector` and `TimeOfDayDetector`, with new alert types\
  `DNS_TUNNELING`, `BEACONING` and `TIME_OF_DAY_ANOMALY`.

* `threat_intel.py`: downloads Emerging Threats and abuse.ch Feodo Tracker blocklists, caches them\
  for 24 h, falls back to the cache or the static blacklist. New alert type `THREAT_INTEL_HIT`.

* `pcap_parser.py`: `.pcap` / `.pcapng` / `.cap` input.

* `streaming.py`: chunked processing with overlapping windows and alert de-duplication.

* `report_generator.py` + `templates/report.html`: self-contained HTML report.

* `streamlit_app.py`: web dashboard.

* `tests/`: 66 pytest tests.

* CLI flags `--version`, `--report`, `--chunk-size`, `--no-v2`, `--update-feeds`,\
  `--no-threat-intel` and `--streamlit`.

* Three new mock-data scenarios (DNS tunneling, beaconing, off-hours).

* A V2 panel on the Rich dashboard.

* New config sections `DNSConfig`, `BeaconingConfig`, `TimeOfDayConfig`, `ThreatFeedConfig`,\
  `PcapConfig`, `StreamingConfig` and `ReportConfig`.

* New dependencies: `dpkt`, `requests`, `jinja2`, `streamlit`, `plotly`, `pytest`.

**Unchanged**

* All V1 commands, alert formats and thresholds work as before. For a given `--seed`, the V1\
  mock-data scenarios are generated exactly as in 1.x.

* V2 features are optional. If one fails, the run shows a warning and the V1 pipeline still finishes.

### 1.x

* Rule-based detection (port scan, brute force, blacklist), Isolation Forest ML detection,\
  public dataset support (CICIDS2017, CSE-CIC-IDS2018, UNSW-NB15), alert logging and the Rich dashboard.

---

## ⚠️ Disclaimer

This is an educational / demo tool. The blacklist uses RFC 5737 documentation ranges\
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), so no real host is implicated.\
Only analyse traffic you are authorised to monitor.
## v2.0.1 bug fixes

- **log_parser**: timestamps with mixed UTC offsets (e.g. across a DST change) crashed parsing (`.dt` on object dtype); now normalised to UTC. CSV files starting with a UTF-8 BOM are read with `utf-8-sig`.
- **threat_intel**: a cache-write failure no longer throws away a successful download; an unreadable fresh cache falls back to the network; `0.0.0.0/0` / `::/0` feed entries are ignored.
- **detection_engine**: any unexpected ML exception is recorded as a warning instead of crashing the pipeline.
- **streamlit_app**: uploaded files are rewritten only when their content changes, so the analysis cache is no longer invalidated on every widget click.
- **alerting**: stale log handlers are removed when a logger name (based on `id()`) is reused.
- New regression tests: `tests/test_bugfixes.py`.
