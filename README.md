![CI](https://github.com/Romil2112/log-analyzer/actions/workflows/ci.yml/badge.svg) ![Python](https://img.shields.io/badge/python-3.12-blue?logo=python&logoColor=white) ![License](https://img.shields.io/badge/license-MIT-green?logo=opensourceinitiative&logoColor=white) ![Open Source](https://img.shields.io/badge/Open%20Source-Free%20to%20Use-success) ![Tests](https://img.shields.io/badge/pytest-146%20passing-brightgreen?logo=pytest&logoColor=white)

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
- **Privacy controls** — optional field-level encryption at rest (`DB_ENCRYPTION_KEY`), username scrubbing (`--scrub-usernames`), raw-line redaction (`--no-raw-lines`), IP pseudonymization (`--pseudonymize`), and data retention (`--retention-days`)
- **GitHub Actions CI** — runs all 146 pytest tests and uploads a sample report on every push

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

## Architecture

It's a straight pipeline. Logs come in, get auto-detected and parsed into one common
event shape, and the rule and ML detectors run over those events. Incidents are then
enriched (threat-intel + GeoIP), mapped to MITRE ATT&CK, and run through the privacy
transforms before anything leaves memory. Whatever's left gets written out — HTML report,
PostgreSQL, Sigma/SIEM files, a push to SOC-Dashboard, and an optional Claude summary.

```mermaid
flowchart LR
    subgraph Ingest
        A[SSH auth.log] --> P
        B[Windows Event CSV] --> P
        C[Apache/Nginx access log] --> P
        P[detect_log_format + parsers] --> E[Common event dicts]
    end
    E --> R[Rule detectors<br/>brute-force · port-scan · 404-flood]
    E --> M[ML anomaly layer<br/>Isolation Forest]
    R --> I[Incidents]
    M --> I
    I --> EN[Enrichment<br/>threat-intel + GeoIP]
    EN --> MI[MITRE ATT&CK mapping]
    MI --> PR[Privacy transforms<br/>scrub · redact · pseudonymize]
    PR --> OUT{Outputs}
    OUT --> H[HTML report]
    OUT --> DB[(PostgreSQL)]
    OUT --> SG[Sigma / SIEM export]
    OUT --> SOC[SOC-Dashboard push]
    OUT --> AI[Claude AI summary]
```

Plaintext view of the same flow:

```
logs ─▶ parse (auto-detect) ─▶ events
                                 ├─▶ rule detectors ─┐
                                 └─▶ ML anomaly ─────┴─▶ incidents
                                       ─▶ enrich (TI+GeoIP) ─▶ MITRE map
                                       ─▶ privacy transforms
                                       ─▶ { HTML · PostgreSQL · Sigma/SIEM · SOC push · AI summary }
```

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
| `--format {ssh,windows,web,auto}` | `auto` | Log format override |
| `--export-sigma DIR` | — | Write vendor-neutral Sigma rules for observed incidents |
| `--export-siem DIR` | — | Compile native Splunk SPL / Elastic ES&#124;QL / Sentinel KQL queries |
| `--push-soc URL` | — | POST detected incidents to a SOC-Dashboard ingestion endpoint |
| `--scrub-usernames` | — | Replace usernames with SHA-256 pseudonyms before storage/reporting |
| `--no-raw-lines` | — | Do not store or report original raw log lines (may contain PII) |
| `--pseudonymize` | — | Replace source IPs with stable per-run HMAC pseudonyms (in-memory only) |
| `--retention-days N` | `0` | Delete events/incidents older than N days after processing (0 = keep forever) |
| `--init-schema` | — | Create database schema and exit |

## Environment Variables

All optional. Unset any of them and the tool falls back to a sensible default — plaintext storage, country `Unknown`, no AI summary, and so on.

| Variable | Used by | Default | Purpose |
|---|---|---|---|
| `LOG_ANALYZER_DSN` | PostgreSQL storage | `postgresql://postgres:postgres@localhost:5432/log_analyzer` | Connection string for `--init-schema` and DB storage (override with `--dsn`) |
| `DB_ENCRYPTION_KEY` | encryption at rest | unset (plaintext) | Fernet key; when set, sensitive fields are encrypted before storage. Generate with `python -c "import secrets;print(secrets.token_hex(32))"` |
| `ANTHROPIC_API_KEY` | `--ai-summary`, `ai_scale.py` | unset | Anthropic API key for Claude executive summaries |
| `GEOIP_DB_PATH` | GeoIP enrichment | unset (country = `Unknown`) | Path to a MaxMind GeoLite2-Country `.mmdb` file |
| `SOC_ALERTS_API_KEY` | `--push-soc` | unset (warns) | `X-API-Key` sent to the SOC-Dashboard ingest endpoint (override with `--soc-api-key`) |

## HTML Report

![Summary cards and charts](docs/1.png)

![Charts and ML anomaly scores](docs/2.png)

![ML detection and incident tables](docs/3.png)

## Project Structure

```
log-analyzer/
├── log_analyzer.py        # Main CLI — parsing, detection, ML, report generation
├── crypto.py              # Fernet field-level encryption helpers (encryption at rest)
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
│   ├── test_contract.py   # producer/consumer event-contract tests
│   └── test_privacy.py    # encryption, scrubbing, pseudonymization, retention (146 total)
└── .github/workflows/
    └── ci.yml             # GitHub Actions: test + report artifact
```

## Running tests

```bash
python -m pytest tests/ -v
```

Run with coverage (the suite is kept at ≥85% line / ≥80% branch, every source module ≥85%):

```bash
python -m pytest --cov=. --cov-branch --cov-report=term-missing
```

## Contributing

Contributions are welcome. A few things that keep the codebase consistent:

- Code is [ruff](https://docs.astral.sh/ruff/)-clean under the rules in `pyproject.toml`
  (E/W/F/I/N/UP/B) — run `ruff check .` before you open a PR.
- Annotate public functions with type hints. The code is written to stay `mypy`-friendly
  (`ignore_missing_imports` covers the optional third-party stubs).
- Public functions, classes, and modules get Google-style docstrings, with
  `Args:` / `Returns:` / `Raises:` where it isn't obvious.
- Add or update tests for anything that changes behaviour, and keep coverage above the bar
  noted under *Running tests*. Parsers and detectors are wired together by the
  `contracts.py` check, so a new event type needs a parser that actually produces it.
- CI runs the whole pytest suite on every push — a PR has to be green to merge.

## Privacy & Legal Compliance

log-analyzer processes security logs that routinely contain **personal data** — source IP
addresses, usernames, and raw log lines. Depending on jurisdiction these may be regulated
under the **GDPR, CCPA**, and similar laws. The controls below let you minimize and protect
that data; lawful, compliant operation remains the operator's responsibility.

### Data Collected

| Field | Sensitivity | Default handling |
|---|---|---|
| `source_ip` | PII | Stored; encrypt with `DB_ENCRYPTION_KEY`, pseudonymize with `--pseudonymize` |
| `username` | PII | Stored; encrypt with `DB_ENCRYPTION_KEY`, hash with `--scrub-usernames` |
| `raw_line` | May contain PII | Stored; encrypt with `DB_ENCRYPTION_KEY`, suppress with `--no-raw-lines` |
| event/incident metadata (type, time, counts, severity) | Non-personal | Stored as-is |

### Pseudonymization / Scrubbing / Redaction

These opt-in flags transform data **after** detection and enrichment (so detection accuracy
is unchanged) and **before** anything is displayed, written to the report, or stored:

- `--pseudonymize` — replaces each source IP with a stable per-run HMAC-SHA256 pseudonym
  (`ip_<hash>`). The random session key and the IP→pseudonym mapping live **in memory only**
  and are never written to disk, so pseudonyms are consistent within a run but not linkable
  across runs.
- `--scrub-usernames` — replaces usernames with `user_<sha256[:8]>` hashes.
- `--no-raw-lines` — stores `NULL` instead of the original log line and omits it from reports.

### Data Retention

`--retention-days N` deletes `log_events` (by `event_time`) and `incidents` (by `first_seen`)
older than *N* days once processing completes. `0` (the default) keeps data forever.

### Encryption at Rest (`DB_ENCRYPTION_KEY`)

Setting `DB_ENCRYPTION_KEY` transparently encrypts the PII columns
(`log_events.source_ip`, `username`, `raw_line` and `incidents.source_ip`) with Fernet
(AES-128-CBC + HMAC) before they are written to PostgreSQL. Generate a key with:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

- If unset, encryption is **disabled gracefully** and values are stored as plaintext. The CLI
  prints whether encryption is `ACTIVE` or `DISABLED` at startup.
- ⚠️ **Rotating `DB_ENCRYPTION_KEY` without re-encrypting existing rows makes previously
  encrypted data unreadable.** Keep the key stable, or re-encrypt on rotation.

When pushing to a SOC dashboard, prefer an **HTTPS** endpoint — `--push-soc` warns when the
URL is plaintext `http://` because IPs and usernames would otherwise traverse the network
unencrypted.

### Authorized Use Only

Use log-analyzer only on systems and logs that **you own or are explicitly authorized to
analyze**. Unauthorized access to or monitoring of computer systems and logs may violate the
U.S. **CFAA**, the UK **Computer Misuse Act**, EU cybercrime / information-systems laws, and
similar statutes.

### Open Source & Responsible Use

This is free and open-source software provided **as-is, without warranty**, as a
demonstration / learning project — not an audited commercial security product. See
[Legal Notice & Responsible Use](#️-legal-notice--responsible-use) and
[SECURITY.md](SECURITY.md).

### No Warranty

The software is provided "as is" under the MIT License, without warranty of any kind. The
operator bears responsibility for lawful use and for compliance with all applicable
data-protection and computer-misuse laws.

## License

MIT — see [LICENSE](LICENSE).

## ⚖️ Legal Notice & Responsible Use

This project is **free and open-source software**, released under the **MIT License** as a
**demonstration / learning / trial project**. It is provided **"as is", without warranty of
any kind**, and is **not an audited or certified commercial security product**.

- **Authorized use only.** Use it solely on systems, networks, and logs that you own or are
  **explicitly authorized** to analyze.
- **Do no harm.** Do not use it to surveil, stalk, harass, invade the privacy of, or conduct
  unauthorized monitoring of any person or organization.
- **Compliance is the operator's responsibility.** Logs may contain IP addresses, usernames,
  and other personal data. Compliance with **GDPR, CCPA, HIPAA, and equivalent laws** — where
  applicable — rests with the operator.
- **Misuse may be illegal.** Unauthorized access to or monitoring of computer systems may
  violate laws such as the U.S. **CFAA**, the UK **Computer Misuse Act**, and EU
  information-systems directives.

By using this software you accept responsibility for operating it lawfully. See
[SECURITY.md](SECURITY.md) to report a vulnerability.
