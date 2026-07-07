![CI](https://github.com/Romil2112/log-analyzer/actions/workflows/ci.yml/badge.svg) ![Python](https://img.shields.io/badge/python-3.12-blue?logo=python&logoColor=white) ![License](https://img.shields.io/badge/license-MIT-green?logo=opensourceinitiative&logoColor=white) ![Open Source](https://img.shields.io/badge/Open%20Source-Free%20to%20Use-success) ![Tests](https://img.shields.io/badge/pytest-195%20passing-brightgreen?logo=pytest&logoColor=white)

# log-analyzer

log-analyzer is a command-line security tool. It reads SSH `auth.log`, Windows Event Log CSV exports, and Apache/Nginx access logs, runs both rule-based and machine-learning detection over them, and maps each finding to a MITRE ATT&CK technique. It writes a dark-themed HTML incident report, and can also store results in PostgreSQL, compile detections into Splunk, Elastic, and Sentinel queries, or push incidents to the companion [SOC-Dashboard](https://github.com/Romil2112/SOC-Dashboard). It is the detection stage of a two-part pipeline: log-analyzer finds the incidents, SOC-Dashboard is where an analyst triages them.

## Screenshots

The HTML incident report: attack overview, MITRE ATT&CK coverage, per-IP anomaly scores, and the detected incidents. It renders offline with no external assets.

![HTML incident report](docs/report.png)

Detection to triage, orchestrated end to end with Orkes Conductor: a 10,000-event log runs
through the three-task workflow and the detected incidents land in the SOC-Dashboard queue.
More detail in [CONDUCTOR.md](CONDUCTOR.md).

![Conductor pipeline walkthrough](docs/pipeline_demo.gif)

## How it works

Logs arrive in one of three formats. `detect_log_format` picks the parser, and every parser emits the same event-dictionary shape, so the detectors downstream never depend on where an event came from. Two detectors run over those events: a rule engine using sliding time windows (brute force T1110.001, port scan T1046, 404-flood and web-scan T1595.002), and an Isolation Forest model that scores each source IP on eight behavioral features to catch the low-and-slow activity the rules miss. Incidents from both are enriched with threat-intel and GeoIP, mapped to ATT&CK, and run through the privacy transforms before anything leaves memory. The outputs then fan out: HTML report, PostgreSQL, Sigma/SIEM files, a SOC-Dashboard push, and an optional Claude summary.

The rule engine's burst detector was the one hot spot. The burst detector started as an O(n²) scan that compared every event against every other event to find pairs inside the window, which took 53 seconds on a 50,000-line log. Since the events are already sorted by time, I replaced it with a two-pointer sweep over a time-sorted window: advance the right edge, drop events off the left once they age out of the window, and count what sits between. That took the same run down to 0.8 seconds, about 69 times faster, and the feature vectors come out bit-for-bit identical, so the Isolation Forest scores are unchanged.

## Features

- Multi-format parsing: SSH `auth.log`, Windows Event Log CSV, and Apache/Nginx access logs, auto-detected
- Rule detection: sliding-window brute force, port scan, and 404-flood / web-scan
- ML anomaly detection: Isolation Forest on 8 behavioral features per source IP
- MITRE ATT&CK mapping: T1110.001, T1046, and T1595.002, each with tactic label and documentation link
- IP enrichment: known-bad CIDR threat-intel feed plus optional MaxMind GeoLite2 country lookup
- Sigma export (`--export-sigma`): vendor-neutral detection-as-code
- Native SIEM compilation (`--export-siem`): Splunk SPL, Elastic ES|QL, and Sentinel KQL via pySigma backends with per-SIEM field-mapping pipelines
- SOC-Dashboard handoff (`--push-soc`): POSTs each incident to the triage queue with `X-API-Key` auth
- Optional orchestration (Orkes Conductor): run the detect, summarize, and push stages as durable, retryable, observable tasks — see [CONDUCTOR.md](CONDUCTOR.md)
- Claude API summaries (`--ai-summary`): concurrent batched calls with token-cost and p50/p95 latency instrumentation, about 8x the throughput of sequential calls
- Encryption at rest: Fernet field-level encryption of PII columns
- Privacy controls: IP pseudonymization, username scrubbing, raw-line redaction, and retention purge
- Fail-loud event contract: a startup check that every detector's required event types are produced by some parser
- Measured detection quality: a labeled-corpus [evaluation harness](eval/) reports precision / recall / F1 on synthetic and real Loghub data
- 195 pytest tests at 90% line / 88% branch coverage, run on GitHub Actions

## Quick Start

Prerequisites: Python 3.12+. PostgreSQL 14+ is optional (use `--no-db` to skip it). An Anthropic API key is optional and only needed for `--ai-summary`.

Install:

```bash
pip install -r requirements.txt
```

Run against a single log with no database, writing a report:

```bash
python log_analyzer.py auth.log --no-db --report report.html
```

Or bring up PostgreSQL and the analyzer together:

```bash
docker compose up
```

Configuration is read from environment variables (see the table below); all of them are optional and fall back to a sensible default.

## CLI flags

| Flag | Default | Description |
|---|---|---|
| `--report FILE` | `incident_report.html` | Output HTML report path |
| `--no-db` | — | Skip PostgreSQL storage |
| `--no-ml` | — | Skip Isolation Forest |
| `--ai-summary` | — | Generate a Claude AI executive summary |
| `--ml-threshold FLOAT` | `0.5` | Minimum anomaly score to display |
| `--brute-force-threshold N` | `5` | Failed logins to trigger an alert |
| `--brute-force-window MIN` | `10` | Sliding window in minutes |
| `--port-scan-threshold N` | `20` | Unique ports to trigger an alert |
| `--port-scan-window MIN` | `5` | Sliding window in minutes |
| `--flood-404-threshold N` | `30` | 404 requests to trigger an alert |
| `--flood-404-window MIN` | `5` | Sliding window in minutes |
| `--allowlist CIDR,...` | — | Comma-separated IPs/CIDRs to exclude from detection |
| `--format {ssh,windows,web,auto}` | `auto` | Log format override |
| `--export-sigma DIR` | — | Write vendor-neutral Sigma rules for observed incidents |
| `--export-siem DIR` | — | Compile native Splunk SPL / Elastic ES&#124;QL / Sentinel KQL queries |
| `--push-soc URL` | — | POST detected incidents to a SOC-Dashboard ingest endpoint |
| `--soc-api-key KEY` | — | `X-API-Key` for `--push-soc` (or set `SOC_ALERTS_API_KEY`) |
| `--scrub-usernames` | — | Replace usernames with SHA-256 pseudonyms before storage/reporting |
| `--no-raw-lines` | — | Do not store or report original raw log lines (may contain PII) |
| `--pseudonymize` | — | Replace source IPs with stable per-run HMAC pseudonyms (in-memory only) |
| `--retention-days N` | `0` | Delete events/incidents older than N days after processing (0 = keep forever) |
| `--init-schema` | — | Create the database schema and exit |

### Environment variables

All optional. Unset any of them and the tool falls back to a sensible default: plaintext storage, country `Unknown`, no AI summary, and so on.

| Variable | Used by | Default | Purpose |
|---|---|---|---|
| `LOG_ANALYZER_DSN` | PostgreSQL storage | `postgresql://postgres:postgres@localhost:5432/log_analyzer` | Connection string for `--init-schema` and DB storage (override with `--dsn`) |
| `DB_ENCRYPTION_KEY` | encryption at rest | unset (plaintext) | Fernet key; when set, sensitive fields are encrypted before storage. Generate with `python -c "import secrets;print(secrets.token_hex(32))"` |
| `ANTHROPIC_API_KEY` | `--ai-summary`, `ai_scale.py` | unset | Anthropic API key for Claude executive summaries |
| `GEOIP_DB_PATH` | GeoIP enrichment | unset (country = `Unknown`) | Path to a MaxMind GeoLite2-Country `.mmdb` file |
| `SOC_ALERTS_API_KEY` | `--push-soc` | unset (warns) | `X-API-Key` sent to the SOC-Dashboard ingest endpoint (override with `--soc-api-key`) |

## Architecture diagram

Logs come in, get auto-detected and parsed into one common event shape, and the rule and ML detectors run over those events. Incidents are enriched (threat-intel + GeoIP), mapped to MITRE ATT&CK, and run through the privacy transforms before anything leaves memory. Whatever remains is written out: HTML report, PostgreSQL, Sigma/SIEM files, a push to SOC-Dashboard, and an optional Claude summary.

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

## Tests

195 pytest tests cover parsing, both detectors, enrichment, MITRE mapping, the privacy transforms, Sigma and SIEM export, the SOC push, and the concurrent Claude layer, at 90% line and 88% branch coverage. Twelve adversarial fixture logs exercise slow brute force, coordinated multi-IP attacks, IPv6, unicode, malformed lines, and high volume. Run the suite with:

```bash
python -m pytest tests/ -v
```

With coverage (kept at ≥85% line / ≥80% branch, every source module ≥85%):

```bash
python -m pytest --cov=. --cov-branch --cov-report=term-missing
```

## Evaluation

Passing tests show the code runs; they do not show the detectors classify well. The [`eval/`](eval/) harness answers that separately, scoring the pipeline against **ground-truth labels** (per source IP, the unit the detectors emit) and reporting precision, recall, F1, and the explicit false-positive and false-negative lists. It runs in three configurations so the contribution of each layer is measurable: `rules`, `rules+fp_reduction`, and `full` (rules + FP suppression + the Isolation Forest anomaly layer).

**Synthetic corpus** — 24 IPs (6 malicious / 18 benign), ground truth known by construction, with two deliberate false-positive traps (a fat-fingered legit user and an internal monitoring account):

| config | precision | recall | F1 |
|--------|-----------|--------|----|
| rules | 0.714 | 0.833 | 0.769 |
| rules+fp_reduction | **1.000** | 0.833 | 0.909 |
| full | 0.857 | **1.000** | 0.923 |

The FP-reduction levers remove both traps (precision 0.71 → 1.00); the anomaly layer then recovers the slow credential-stuffer the rules structurally miss (recall 0.83 → 1.00) at the cost of one honest false positive on a high-volume gateway. That trade-off is real, and it is the point — a 1.0/1.0 would mean the corpus was rigged.

**Real data** — Loghub "LabSZ" OpenSSH capture (`logpai/loghub`), an internet-facing server under continuous brute-force, 24 IPs (23 malicious / 1 benign), labeled by dataset domain knowledge independent of the detector threshold:

| config | precision | recall | F1 |
|--------|-----------|--------|----|
| rules | 1.000 | 0.391 | 0.562 |
| full | 1.000 | 0.391 | 0.562 |

Two findings the harness makes honest instead of hand-waved:

- The fixed count threshold has perfect precision but **39% recall** — it catches the 9 high-volume attackers and misses 14 low-and-slow ones. That is the quantified cost of a threshold.
- The **ML layer adds nothing here**, unlike on the synthetic corpus. When ~96% of the traffic is already attacking, "anomalous versus the crowd" breaks down — Isolation Forest assumes attackers are rare outliers, and on a saturated log they are the baseline. Knowing when unsupervised anomaly detection helps (mostly-benign traffic) versus when it doesn't (saturated attack) is the takeaway.

**A false positive this harness caught, and the fix.** The evaluation surfaced a real defect: `detect_port_scan` was double-flagging brute-forcers. SSH clients use a random ephemeral *source* port per attempt, which the parser stored in the same `port` field, so one attacker's many failed logins looked like many distinct "ports." The fix is a single predicate — count only `event_type == "connection"` events, since an auth event's port is the client's source port, not a scanned destination. Measured result: port_scan false positives dropped 6 → 0 (synthetic 2, real Loghub 4), port_scan F1 rose 0.40 → 1.00, both genuine scanners were preserved, and the per-IP metrics above were unchanged. Two regression tests in `tests/test_detection.py` now lock it out. Full method, corpus provenance, and how to label your own data are in [`eval/README.md`](eval/README.md).

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
