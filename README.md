![Python](https://img.shields.io/badge/python-3.14-blue?logo=python&logoColor=white) ![License](https://img.shields.io/badge/license-MIT-green?logo=opensourceinitiative&logoColor=white) ![Tests](https://img.shields.io/badge/pytest-61%20passing-brightgreen?logo=pytest&logoColor=white)

# log-analyzer

A CLI security tool that parses SSH `auth.log` and Windows Event Log CSV files, detects attacks with rule-based and ML detection, maps findings to MITRE ATT&CK, and generates a dark-themed HTML incident report.

## Features

- **Rule-based detection** — sliding-window brute-force, port scan, and 404-flood alerts
- **ML anomaly detection** — Isolation Forest on 8 behavioural features per source IP; catches low-and-slow attackers rules miss
- **MITRE ATT&CK mapping** — every incident tagged with technique ID, tactic, and documentation link
- **Rich CLI** — colour-coded tables, severity badges (CRITICAL/HIGH/MEDIUM/LOW), and live progress bars
- **Claude AI summaries** — 3-sentence SOC executive summary via the Anthropic API (`--ai-summary`)
- **HTML reports** — Chart.js dashboards: timeline, top-attacker IPs, event breakdown, ML anomaly scores
- **Docker support** — `docker compose up` spins up Postgres + analyzer together
- **GitHub Actions CI** — runs all 61 pytest tests and uploads a sample report on every push

## Quick start

```bash
pip install -r requirements.txt

# No database
python log_analyzer.py auth.log --no-db --report report.html

# With PostgreSQL
python log_analyzer.py auth.log --report report.html

# With Claude AI executive summary
export ANTHROPIC_API_KEY=sk-...
python log_analyzer.py auth.log --no-db --ai-summary --report report.html

# Via Docker (place log at ./logs/auth.log)
docker compose up
```

## CLI flags

| Flag | Default | Description |
|---|---|---|
| `--report FILE` | `incident_report.html` | Output HTML report path |
| `--no-db` | — | Skip PostgreSQL storage |
| `--no-ml` | — | Skip Isolation Forest |
| `--ai-summary` | — | Generate Claude AI executive summary |
| `--ml-threshold FLOAT` | `0.5` | Minimum anomaly score to display |
| `--brute-force-threshold N` | `5` | Failed logins to trigger alert |
| `--brute-force-window MIN` | `10` | Sliding window in minutes |
| `--port-scan-threshold N` | `20` | Unique ports to trigger alert |
| `--port-scan-window MIN` | `5` | Sliding window in minutes |
| `--format {ssh,windows,auto}` | `auto` | Log format override |
| `--init-schema` | — | Create database schema and exit |

## Running tests

```bash
python -m pytest tests/ -v
```

## License

MIT
