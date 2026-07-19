# Detection Rule Changelog

All changes to detection logic, thresholds, and rule versioning are documented here.

## [1.1.0] — 2026-07-18

### Added
- `DETECTION_RULES_VERSION = "1.1.0"` constant; included in HTML report footer, SOC-push payload, and evaluation_report.json.
- `--allowlist-file <path>`: YAML-based allowlist supporting ips (CIDR), usernames, and hostnames.
- `--config <path>`: YAML config file support for per-rule threshold overrides (`thresholds:` section).
- `--suppress-repeats <minutes>`: suppress duplicate (type+IP) incidents already stored within the window.
- `--evaluate <csv>`: precision/recall/F1 evaluation against a labeled ground-truth CSV; writes evaluation_report.json.
- `--eval-tolerance <minutes>`: configurable time-proximity window for ground-truth matching (default: ±5 min).
- `--replay-compare <config_a.yaml> <config_b.yaml>`: dry-run A/B comparison of two threshold configs.

## [1.0.0] — 2026-01-01

### Initial release
- Rule-based detection: brute force (T1110.001), port scan (T1046), 404-flood (T1595.002).
- Isolation Forest ML anomaly detection (8 behavioral features).
- MITRE ATT&CK mapping, GeoIP + threat-intel enrichment.
- HTML incident report, PostgreSQL storage, Sigma/SIEM export, SOC-Dashboard push.
- Privacy controls: pseudonymization, username scrubbing, raw-line redaction, retention purge.
- Fernet field-level encryption at rest.
