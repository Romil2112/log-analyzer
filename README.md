![CI](https://github.com/Romil2112/log-analyzer/actions/workflows/ci.yml/badge.svg) ![Python](https://img.shields.io/badge/python-3.12-blue?logo=python&logoColor=white) ![License](https://img.shields.io/badge/license-MIT-green?logo=opensourceinitiative&logoColor=white) ![Tests](https://img.shields.io/badge/pytest-136%20passing-brightgreen?logo=pytest&logoColor=white)

# log-analyzer

A CLI security tool that parses SSH `auth.log` and Windows Event Log CSV files, detects attacks with rule-based and ML detection, maps findings to MITRE ATT&CK, and generates a dark-themed HTML incident report.

## Features

- **Multi-source parsing** — SSH `auth.log`, Windows Event Log CSV, and Apache/Nginx access logs (auto-detected)
- **Rule-based detection** — sliding-window brute-force, port scan, and 404-flood / web-scan alerts
- **ML anomaly detection** — Isolation Forest on 8 behavioural features per source IP; catches low-and-slow attackers rules miss
- **MITRE ATT&CK mapping** — every incident tagged with technique ID, tactic, and documentation link
- **IP enrichment** — threat-intel reputation (known-bad CIDR feed) + optional MaxMind GeoLite2 GeoIP country
- **Sigma export** — emit detections as vendor-neutral [Sigma](https://github.com/SigmaHQ/sigma) rules (`--export-sigma`), SIEM-portable via the Sigma CLI
- **Native SIEM compilation** — `--export-siem` compiles detections into ready-to-run **Splunk SPL**, **Elastic ES|QL**, and **Microsoft Sentinel KQL** queries using real [pySigma](https://github.com/SigmaHQ/pySigma) backends + per-SIEM field-mapping pipelines (Splunk CIM / ECS / ASIM), with the count/timespan thresholds expressed as Sigma correlation rules
- **SOC-Dashboard handoff** — `--push-soc <url>` POSTs detected incidents straight into the [SOC-Dashboard](https://github.com/Romil2112/SOC-Dashboard) triage queue (Detect → Triage)
- **Rich CLI** — color-coded tables, severity badges (CRITICAL/HIGH/MEDIUM/LOW), and live progress bars
- **Claude AI summaries** — 3-sentence SOC executive summary via the Anthropic API (`--ai-summary`)
- **AI summaries at scale** — concurrent batch summarization (`ai_scale.py`) with bounded concurrency, retry/backoff on rate limits, and per-run token-cost + latency (p50/p95) instrumentation
- **HTML reports** — Chart.js dashboards: timeline, top-attacker IPs, event breakdown, ML anomaly scores
- **Docker support** — `docker compose up` spins up Postgres + analyzer together
- **Fail-loud event contract** — a startup/CI check (`contracts.py`) asserts every detector's required event types are produced by some parser, so an "orphaned detector" can't silently run and find nothing
- **GitHub Actions CI** — runs all 136 pytest tests and uploads a sample report on every push

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.12+ | |
| PostgreSQL | 14+ | Optional — use `--no-db` to skip |
| Anthropic API key | — | Optional — only needed for `--ai-summary` |

## Skills Demonstrated

| Area | Details |
|---|---|
| Security Detection | Sliding-window brute-force, port scan, and 404-flood rule engine over SSH/Windows/web logs |
| Detection-as-Code | Vendor-neutral Sigma rules **plus** native Splunk SPL / Elastic ES|QL / Sentinel KQL compiled with pySigma backends and per-SIEM field-mapping pipelines |
| Threat Intel / GeoIP | Known-bad CIDR reputation matching + optional MaxMind GeoLite2 country enrichment |
| ML / Anomaly Detection | Isolation Forest on 8 behavioural features; catches low-and-slow attacks |
| MITRE ATT&CK | Technique mapping (T1110.001, T1046, T1595.002), tactic labelling, clickable report links |
| PostgreSQL | Schema design, psycopg2 batch inserts, JSONB incident details |
| Docker | Multi-service Compose with health-checked Postgres and volume mounts |
| CI/CD | GitHub Actions: pytest gate + HTML report artifact on every push |
| Claude AI / Anthropic | API integration, SOC executive summary generation, prompt engineering |
| LLM at scale | Concurrent batch summarization with retry/backoff, rate-limit handling, and token-cost + p50/p95 latency instrumentation (benchmarked ~8× throughput at concurrency 8) |

## Demo

```
┌─────────────────────────────────────────────────────────────────────┐
│  Log Analyzer  │  test_auth_10k.log  │  format: ssh  │  10,000 lines │
└─────────────────────────────────────────────────────────────────────┘
[+] Parsed 10,000 events  (10,000 lines)
[*] Running rule-based detections...

                          Detected Incidents
╭──────────────┬─────────────────┬───────┬──────────┬────────────────────╮
│ Type         │ Source IP       │ Count │ Severity │ MITRE ID           │
├──────────────┼─────────────────┼───────┼──────────┼────────────────────┤
│ Brute Force  │ 10.99.99.99     │  2311 │ CRITICAL │ T1110.001          │
│ Port Scan    │ 10.99.99.99     │   512 │ CRITICAL │ T1046              │
│ Port Scan    │ 198.51.100.77   │    87 │ HIGH     │ T1046              │
│ Port Scan    │ 203.0.113.42    │    54 │ MEDIUM   │ T1046              │
│ Brute Force  │ 185.220.101.45  │   430 │ CRITICAL │ T1110.001          │
│ Brute Force  │ 45.33.32.156    │   218 │ CRITICAL │ T1110.001          │
│ Brute Force  │ 198.199.119.48  │    97 │ HIGH     │ T1110.001          │
╰──────────────┴─────────────────┴───────┴──────────┴────────────────────╯

  MITRE ATT&CK Coverage
  T1110.001  Brute Force: Password Guessing  Credential Access  (4 incidents)
  T1046      Network Service Discovery       Discovery          (3 incidents)

[+] Isolation Forest — 4 IPs above threshold 0.5
  10.99.99.99    score=1.0000  Rule + ML
  91.108.4.200   score=0.6196  ML Only
  172.16.0.0     score=0.6111  ML Only
  203.0.113.42   score=0.5067  Rule + ML

[+] Report written: report.html
```

> The demo runs against `test_auth_10k.log`, a 10,000-event SSH fixture produced by
> `python generate_test_logs.py --scale` (gitignored, generated on demand). The 12
> `test_*.log` files committed to the repo are ready-to-use fixtures for the test suite.

## Quick Start

### Install
```bash
pip install -r requirements.txt
```

### No database
```bash
python log_analyzer.py auth.log --no-db --report report.html
```

### With PostgreSQL
```bash
python log_analyzer.py auth.log --report report.html
```

### Web access logs (Apache/Nginx)
```bash
# Auto-detects the access-log format and runs 404-flood / web-scan detection
python log_analyzer.py access.log --no-db --report report.html
```

### Threat-intel + GeoIP enrichment
```bash
# Uses the bundled known-bad CIDR feed by default; add your own and a GeoIP DB
python log_analyzer.py auth.log --no-db \
  --threat-intel-file my_badips.txt \
  --geoip-db GeoLite2-Country.mmdb
```

### Export Sigma rules (detection-as-code)
```bash
python log_analyzer.py auth.log --no-db --export-sigma ./sigma_rules
```

### Compile native SIEM queries (Splunk / Elastic / Sentinel)
```bash
# Writes brute_force.spl / .esql / .kql (etc.) — one file per detection per SIEM
python log_analyzer.py auth.log --no-db --export-siem ./siem_queries
```

Example output (`brute_force.spl`, Splunk CIM field schema):

```spl
event_type="failed_login"
| bin _time span=10m
| stats count as event_count by _time src_ip
| search event_count >= 5
```

The same detection in Microsoft Sentinel KQL (`brute_force.kql`, ASIM field schema):

```kql
event_type =~ "failed_login"
| summarize event_count = count() by bin(TimeGenerated, 10m), SrcIpAddr
| where event_count >= 5
```

### Push detections into the SOC-Dashboard queue
```bash
# Detect, then POST each incident to the companion SOC-Dashboard for triage
python log_analyzer.py access.log --no-db --push-soc http://localhost:8000/api/alerts
```

### With AI summary

```bash
export ANTHROPIC_API_KEY=sk-ant-your-key-here
python log_analyzer.py auth.log --no-db --ai-summary --report report.html
```

### AI summaries at scale

When summarizing many incident groups, `ai_scale.summarize_batch` runs the
Claude calls concurrently with a bounded worker pool, retries rate-limit /
transient errors with exponential backoff, and records token cost and latency:

```python
from ai_scale import summarize_batch, build_client, build_incident_prompt
prompts = [build_incident_prompt(group) for group in incident_groups]
summaries, metrics = summarize_batch(prompts, client=build_client(), max_concurrency=8)
print(metrics.as_dict())
# {'succeeded': 200, 'failed': 0, 'retries': 0, 'cost_usd': 0.084,
#  'p50_ms': ..., 'p95_ms': ..., 'throughput_per_s': 147.7, ...}
```

Benchmark the concurrency layer (latency-simulating stub, no live API calls):

```bash
python benchmark_ai.py --n 200 --latency 0.05 --concurrency 8
# serial (c=1):  18.5 summaries/s ; concurrent (c=8): 147.7/s  → ~8x speedup
```

### Via Docker
```bash
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
| `--flood-404-threshold N` | `30` | 404 requests to trigger alert |
| `--flood-404-window MIN` | `5` | Sliding window in minutes |
| `--allowlist CIDR,...` | — | Comma-separated IPs/CIDRs to exclude from detection |
| `--format {ssh,windows,auto}` | `auto` | Log format override |
| `--export-sigma DIR` | — | Write vendor-neutral Sigma rules for observed incidents |
| `--export-siem DIR` | — | Compile native Splunk SPL / Elastic ES&#124;QL / Sentinel KQL queries |
| `--push-soc URL` | — | POST detected incidents to a SOC-Dashboard ingestion endpoint |
| `--init-schema` | — | Create database schema and exit |

## HTML Report

![Summary cards and charts](docs/1.png)

![Charts and ML anomaly scores](docs/2.png)

![ML detection and incident tables](docs/3.png)

## Project Structure

```
log-analyzer/
├── log_analyzer.py        # Main CLI — parsing, detection, ML, report generation
├── ai_summary.py          # Claude API executive summary integration
├── ai_scale.py            # Concurrent batch summarization + token-cost/latency metrics
├── sigma_export.py        # Vendor-neutral Sigma rule export (detection-as-code)
├── siem_export.py         # pySigma backends → native Splunk SPL / Elastic ES|QL / Sentinel KQL
├── contracts.py           # Producer/consumer event-type contract (fail-loud check)
├── benchmark_ai.py        # Concurrency benchmark (stubbed, no live API calls)
├── generate_test_logs.py  # Synthetic SSH + Windows log generator
├── schema.sql             # PostgreSQL schema (log_events, incidents)
├── requirements.txt       # Python dependencies
├── config.example.yaml    # All detection thresholds and allowlist options
├── Dockerfile             # Container image
├── docker-compose.yml     # Postgres + analyzer services
├── test_auth_50k.log      # 50,000-event SSH scale fixture
├── test_highvol.log       # 50,000-event high-volume stress fixture
├── test_coordinated.log   # Coordinated multi-IP (low-and-slow) attack
├── test_slow_brute.log    # Slow credential-stuffing spread over hours
├── test_large_scan.log    # Large port-scan fixture
├── test_mixed.log         # Mixed SSH + web (404-flood) attack
├── test_web_access.log    # Web-access log fixture
├── test_ipv6.log          # IPv6 address parsing fixture
├── test_unicode.log       # Unicode / non-ASCII line handling
├── test_malformed.log     # Malformed / unparseable-line edge cases
├── test_empty.log         # Empty-file edge case
├── test_single.log        # Single-event edge case
│                          # (test_auth_10k.log + test_events.csv are generated on demand — gitignored)
├── tests/
│   ├── test_detection.py  # rule, ML, parsing, DB unit + integration tests
│   ├── test_web_enrichment_sigma.py  # web-log / enrichment / Sigma tests
│   ├── test_siem_export.py  # native SIEM query compilation tests (pySigma)
│   ├── test_soc_push.py   # SOC-Dashboard push tests
│   ├── test_ai_scale.py   # concurrent AI summarization tests
│   └── test_contract.py   # producer/consumer event-contract tests (136 total)
└── .github/workflows/
    └── ci.yml             # GitHub Actions: test + report artifact
```

## Running tests

```bash
python -m pytest tests/ -v
```

## License

MIT
