# log-analyzer

![Python](https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/postgresql-14%2B-336791?logo=postgresql&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)
![psycopg2](https://img.shields.io/badge/psycopg2-2.9%2B-orange)

A CLI security tool that parses SSH `auth.log` and Windows Event Log CSV files, detects **brute force attacks** and **port scans**, stores all events in PostgreSQL, and generates a dark-themed **HTML incident report** with interactive Chart.js visualizations.

---

## Features

- **Dual log format support** — SSH `auth.log` (syslog) and Windows Event Log CSV (EventID 4624/4625)
- **Brute force detection** — flags IPs with 5+ failed logins within a 10-minute sliding window
- **Port scan detection** — flags IPs hitting 20+ unique ports within a 5-minute sliding window
- **PostgreSQL storage** — persists raw events and detected incidents with full timestamps
- **HTML incident report** — 4 interactive Chart.js charts + sortable incident tables, no external dependencies beyond CDN
- **Auto format detection** — sniffs file extension and content, no `--format` flag needed in most cases
- **Configurable thresholds** — override any detection parameter via CLI flags

---

## Screenshots

### Incident Report — Summary Cards & Charts

```
┌─────────────────────────────────────────────────────────────────┐
│  🛡  Log Analyzer — Incident Report                              │
│  Generated 2024-06-15 03:00 UTC  |  Source: auth.log            │
├──────────────┬──────────────┬──────────────┬────────────────────┤
│  48 Events   │  1 Brute     │  1 Port      │  2 Attacker IPs    │
│  Parsed      │  Force       │  Scan        │                    │
└──────────────┴──────────────┴──────────────┴────────────────────┘
```

> **Bar chart** — events by type (failed_login, successful_login, connection)
> **Line chart** — brute force and port scan incidents over time
> **Horizontal bar** — top attacker IPs by failed login count
> **Doughnut** — incident type breakdown

### Brute Force Incidents Table

| Source IP       | Failed Attempts | First Seen          | Last Seen           | Duration |
|-----------------|-----------------|---------------------|---------------------|----------|
| `192.168.1.100` | **12**          | 2024-06-15 02:00:00 | 2024-06-15 02:03:40 | 3m 40s   |

### Port Scan Incidents Table

| Source IP    | Unique Ports | First Seen          | Last Seen           | Sample Ports              |
|--------------|--------------|---------------------|---------------------|---------------------------|
| `10.0.0.55`  | **25**       | 2024-06-15 02:10:00 | 2024-06-15 02:12:48 | `1000, 1050, 1100, 1150…` |

---

## Requirements

- Python 3.9+
- PostgreSQL 14+ (optional — use `--no-db` to skip)

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/log-analyzer.git
cd log-analyzer
pip install -r requirements.txt
```

---

## Database Setup (optional)

Create the database once, then let the tool manage the schema automatically on first run:

```bash
createdb log_analyzer
export LOG_ANALYZER_DSN="postgresql://postgres:yourpassword@localhost:5432/log_analyzer"
```

Or pass the DSN inline per-run:

```bash
python log_analyzer.py auth.log --dsn "postgresql://user:pass@host/db"
```

---

## Usage

### Quickstart (no database)

```bash
python log_analyzer.py /var/log/auth.log --no-db
# report written to incident_report.html
```

### SSH auth.log

```bash
python log_analyzer.py /var/log/auth.log --report ssh_report.html
```

### Windows Event Log CSV

Export from Event Viewer or PowerShell, then:

```bash
python log_analyzer.py security_events.csv --report windows_report.html
```

Expected CSV columns (case-insensitive):
`TimeCreated`, `EventID`, `IpAddress`, `TargetUserName`, `IpPort`

### Custom thresholds

```bash
# Alert on 3+ failures in 5 minutes, port scan at 10+ ports in 2 minutes
python log_analyzer.py auth.log --no-db \
  --brute-force-threshold 3 \
  --brute-force-window 5 \
  --port-scan-threshold 10 \
  --port-scan-window 2
```

### Initialize schema only

```bash
python log_analyzer.py any.log --init-schema
```

---

## CLI Reference

```
usage: log-analyzer [-h] [--dsn DSN] [--report FILE]
                    [--format {ssh,windows,auto}] [--no-db] [--init-schema]
                    [--brute-force-threshold N] [--brute-force-window MINUTES]
                    [--port-scan-threshold N] [--port-scan-window MINUTES]
                    logfile

positional arguments:
  logfile                      Path to the log file (auth.log or Windows Event Log .csv)

options:
  --dsn DSN                    PostgreSQL DSN (default: $LOG_ANALYZER_DSN)
  --report FILE                Output HTML report path (default: incident_report.html)
  --format {ssh,windows,auto}  Log format override (default: auto-detect)
  --no-db                      Skip PostgreSQL storage
  --init-schema                Create/reset DB schema and exit
  --brute-force-threshold N    Failed logins to trigger alert (default: 5)
  --brute-force-window MINUTES Time window in minutes (default: 10)
  --port-scan-threshold N      Unique ports to trigger alert (default: 20)
  --port-scan-window MINUTES   Time window in minutes (default: 5)
```

---

## Database Schema

```sql
-- All parsed log lines
log_events (id, source_file, event_time, log_type, event_type,
            source_ip, username, port, raw_line, ingested_at)

-- Detected incidents
incidents  (id, incident_type, source_ip, first_seen, last_seen,
            event_count, details JSONB, detected_at)
```

---

## Detection Logic

### Brute Force
Sliding-window scan over failed login events per source IP. An incident is raised the first time a window of `--brute-force-window` minutes contains at least `--brute-force-threshold` failures. One incident is recorded per IP per run.

### Port Scan
Same sliding-window approach over all connection events. An incident is raised when a single IP touches at least `--port-scan-threshold` **unique** destination ports within `--port-scan-window` minutes. Detected port list is stored as JSONB in the `incidents` table.

---

## Generating Test Logs

A sample data generator is included:

```bash
python generate_test_logs.py
# Creates test_auth.log (SSH) and test_events.csv (Windows)

python log_analyzer.py test_auth.log --no-db --report report_ssh.html
python log_analyzer.py test_events.csv --no-db --report report_win.html
```

---

## Project Structure

```
log-analyzer/
├── log_analyzer.py        # Main CLI tool
├── generate_test_logs.py  # Test data generator
├── schema.sql             # PostgreSQL schema
├── requirements.txt       # Python dependencies
└── README.md
```

---

## License

MIT — see [LICENSE](LICENSE) for details.
