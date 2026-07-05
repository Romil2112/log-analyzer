![CI](https://github.com/Romil2112/log-analyzer/actions/workflows/ci.yml/badge.svg) ![Python](https://img.shields.io/badge/python-3.12-blue?logo=python&logoColor=white) ![License](https://img.shields.io/badge/license-MIT-green?logo=opensourceinitiative&logoColor=white) ![Open Source](https://img.shields.io/badge/Open%20Source-Free%20to%20Use-success) ![Tests](https://img.shields.io/badge/pytest-193%20passing-brightgreen?logo=pytest&logoColor=white)

# log-analyzer

A command-line tool that reads security logs, flags attacks, maps them to MITRE ATT&CK, and either compiles the detections into SIEM queries or pushes them to a triage dashboard.

## What it reads

It parses three log formats and auto-detects which one it's looking at: SSH `auth.log`, Windows Event Log exported as CSV, and Apache or Nginx access logs.

## Detection

A rule engine watches for brute-force logins (T1110.001), port scans (T1046), and web scans (T1595.002) using sliding time windows. On top of that, an Isolation Forest model scores each source IP on eight behavioral features and catches the slow, quiet attackers that stay under the rule thresholds. Every incident carries its ATT&CK technique ID, tactic, and a documentation link.

## Sending detections somewhere useful

Two options. `--push-soc <url>` POSTs each incident straight into the [SOC-Dashboard](https://github.com/Romil2112/SOC-Dashboard) queue for triage. `--export-siem` compiles the same detections into Splunk SPL, Elastic ES|QL, or Sentinel KQL through pySigma, with per-SIEM field mapping, so you can run them where your data already lives.

## Claude API summaries

The tool can write a short SOC summary of an incident batch with the Claude API. Those calls spend most of their time waiting on the network, so running them one after another is slow. I batch them and run them concurrently with a bounded worker pool, which gets throughput to about 8 times the sequential version. Each run records token cost and p50/p95 latency, so I can see what a summarization pass costs before pointing it at a large log.

## Security controls

Sensitive fields can be encrypted at rest with Fernet. Records carry an HMAC integrity check. There are flags to pseudonymize IP addresses, scrub usernames and raw lines, and drop data past a retention window, so what gets stored stays within what you're allowed to keep.

## Performance

The burst detector looks for bursts of failed logins from one IP inside a time window. My first version compared every event against every other event to find pairs inside the window, which is O(n²) and took 53 seconds on a 50,000-line log. The events are already sorted by time, so I switched to a two-pointer sweep: advance a right pointer, drop events off the left once they fall outside the window, and count what's between. That runs in linear time, and the same log now finishes in 0.8 seconds, about 69 times faster. The feature vectors come out bit-for-bit identical, so the ML scores didn't change.

## Tests

193 pytest tests at 91% line and 88% branch coverage, run on GitHub Actions. The suite includes 12 adversarial fixture logs covering slow brute force, coordinated multi-IP attacks, IPv6, unicode, malformed lines, and high volume.

## Running it

```bash
docker compose up
```

This starts PostgreSQL and the analyzer together. To run against a single log without a database:

```bash
python log_analyzer.py auth.log --no-db
```

## Environment variables

| Variable | Purpose |
|---|---|
| `LOG_ANALYZER_DSN` | PostgreSQL connection string for storage |
| `DB_ENCRYPTION_KEY` | Fernet key; when set, sensitive fields are encrypted at rest |
| `ANTHROPIC_API_KEY` | Enables Claude API summaries |
| `SOC_ALERTS_API_KEY` | `X-API-Key` sent with `--push-soc` |
| `GEOIP_DB_PATH` | Path to a MaxMind GeoLite2 database for country enrichment |
