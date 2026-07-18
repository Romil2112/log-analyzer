# Contributing to log-analyzer

log-analyzer is a Python CLI security tool that detects brute-force attacks, port scans, and
web floods in SSH, Windows Event, and Apache/Nginx logs using rule-based detection and an
Isolation Forest ML layer, mapped to MITRE ATT&CK and optionally summarized by Claude AI.
Contributions of all kinds are welcome — whether that's a new detection rule, an improvement
to the ML pipeline, a new log format parser, or a bug fix.

---

## Ways to Contribute

- **Bug reports** — unexpected output, false positives, parsing failures, crashes
- **New detection rules** — new attack patterns with sliding-window logic and MITRE mapping
- **New log format parsers** — extend the `detect_log_format` pipeline to handle a new format
- **ML improvements** — feature engineering, alternative models, threshold tuning
- **New export formats** — additional SIEM targets beyond Splunk/Elastic/Sentinel
- **Evaluation corpus additions** — labeled log fixtures that expand the `eval/` harness
- **Documentation** — README clarifications, architecture diagrams, usage examples

---

## Getting Started

**Prerequisites:** Python 3.12+. PostgreSQL is optional — all development workflows use `--no-db`.

```bash
# 1. Clone and create a virtual environment
git clone https://github.com/Romil2112/log-analyzer.git
cd log-analyzer
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 2. Install runtime + dev dependencies
pip install -r requirements-dev.txt

# 3. Verify the tool runs against an included fixture log
python log_analyzer.py test_auth_10k.log --no-db --report report.html

# 4. Run the full test suite to confirm your environment is clean
python -m pytest tests/ -v
```

If you plan to work on `--ai-summary` features, you also need an Anthropic API key:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

The key is only required for the `--ai-summary` flag and the `ai_scale.py` benchmarking
script. All other features, including the full test suite, work without it.

---

## Project Structure

```
log_analyzer.py          # Entry point and core pipeline (parsers, detectors, outputs)
ai_summary.py            # Claude AI executive summary — concurrent batched API calls
ai_scale.py              # Latency / cost benchmarking harness for the Claude layer
contracts.py             # Startup event-contract check (fail-loud if a parser/detector mismatch)
enrichment.py            # Threat-intel + MaxMind GeoIP enrichment
crypto.py                # Fernet field-level encryption for PostgreSQL PII columns
export_util.py           # Shared HTML report rendering helpers
sigma_export.py          # Sigma rule generation from detected incidents
siem_export.py           # pySigma backend compilation → Splunk SPL / Elastic ES|QL / Sentinel KQL
soc_push.py              # HTTP POST of incidents to a SOC-Dashboard ingest endpoint
config.example.yaml      # Annotated reference for all environment variables and thresholds
schema.sql               # PostgreSQL schema (log_events + incidents tables)
tests/                   # 195 pytest tests (90% line / 88% branch coverage)
  test_detection.py      # Unit tests for all three detectors + severity scoring
  test_privacy.py        # Pseudonymization, username scrubbing, retention purge
  test_siem_export.py    # Splunk / Elastic / Sentinel query compilation
  test_soc_push.py       # SOC-Dashboard push (mocked HTTP)
  test_ai_scale.py       # Claude layer (mocked Anthropic client)
  test_contract.py       # Event contract startup check
  test_enrichment_and_eval.py  # Threat-intel + GeoIP enrichment
eval/                    # Detection quality harness — precision / recall / F1 against labeled data
  README.md              # How to run the harness and label your own corpus
docs/                    # Screenshots and demo GIFs for the README
```

---

## Adding a New Detection Rule

Detection rules are the most self-contained contribution. Every rule follows the same pattern:

1. **Write the detector function** in `log_analyzer.py`, following the structure of
   `detect_brute_force` or `detect_port_scan`:
   - Accept `events: list[dict]` and threshold/window parameters
   - Use the two-pointer sliding-window pattern (see `detect_brute_force`) — do not use O(n²) scans
   - Return a list of incident dicts with at minimum: `source_ip`, `event_type`, `first_seen`,
     `last_seen`, `count`, `severity`, `mitre_technique`, `mitre_tactic`

2. **Add threshold constants** near the top of `log_analyzer.py` alongside
   `BRUTE_FORCE_THRESHOLD`, `BRUTE_FORCE_WINDOW`, etc., and expose them as CLI flags in
   `parse_args()`.

3. **Map to MITRE ATT&CK** — add an entry to the `MITRE_MAP` dict:
   ```python
   "your_event_type": {
       "technique": "T1XXX.00X",
       "tactic": "Your Tactic",
       "url": "https://attack.mitre.org/techniques/T1XXX/00X/",
   }
   ```

4. **Wire it into `main()`** alongside the existing `detect_brute_force`,
   `detect_port_scan`, and `detect_404_flood` calls.

5. **Add fixture log lines** — add a small synthetic `.log` file in the repo root (e.g.
   `test_yourattack.log`) that exercises both the positive and negative case.

6. **Write tests** in `tests/test_detection.py` using the `make_event()` helper:
   ```python
   def make_event(event_type, source_ip, minutes_offset=0, port=None, log_type="ssh"):
       ...
   ```
   Cover: trigger fires at threshold, does not fire below threshold, respects the sliding
   window, respects the allowlist, and a regression case for any edge condition.

---

## Code Style

The project uses **ruff** for linting and formatting (configured in `pyproject.toml`):

```bash
pip install ruff
ruff check .          # lint
ruff format .         # format (100-character line length)
ruff format --check . # CI-style check without writing
```

Active rule sets: `E`, `W` (PEP 8), `F` (pyflakes), `I` (isort), `N` (pep8-naming),
`UP` (pyupgrade), `B` (bugbear). `E501` (line length) is ignored — long f-string report
lines are intentional. Tests are exempt from `N802`/`N806`.

Type annotations are checked with **mypy**:

```bash
pip install mypy
mypy log_analyzer.py
```

---

## Running Tests

```bash
# Full suite
python -m pytest tests/ -v

# With coverage (maintained at ≥85% line / ≥80% branch, every source module ≥85%)
python -m pytest --cov=. --cov-branch --cov-report=term-missing

# Single file
python -m pytest tests/test_detection.py -v

# Run tests matching a name pattern
python -m pytest -k "brute_force" -v
```

All 195 tests must pass before submitting a PR. The GitHub Actions CI runs the same
`pytest --cov` command on every push.

---

## Running the Evaluation Harness

If your change touches a detector, run the evaluation harness to confirm precision/recall
did not regress:

```bash
cd eval/
python eval.py          # synthetic corpus
python eval.py --real   # Loghub LabSZ real-data corpus
```

See [`eval/README.md`](eval/README.md) for how to label your own corpus and add it to the
harness.

---

## Pull Request Guidelines

- **One change per PR** — a new detection rule, a bug fix, a parser, or a refactor; not
  all at once.
- **Tests are required** — every new function and every bug fix needs a corresponding test
  in the right `tests/test_*.py` file. PRs that drop coverage below 85% line / 80% branch
  will not be merged.
- **Pass CI before requesting review** — ruff, mypy, and pytest all run in GitHub Actions.
  Check the badge at the top of the README.
- **Update `config.example.yaml`** if you add any new CLI flag or environment variable.
- **No Anthropic API key in tests** — any test touching the Claude layer must mock the
  client (see `tests/test_ai_scale.py` for the pattern). Real API calls in tests are not
  acceptable.

---

## Reporting Bugs

Open an issue and include:

- **Command you ran** — the full `python log_analyzer.py ...` invocation with flags
- **Log format** — SSH, Windows CSV, or Apache/Nginx (or paste a few representative lines,
  redacted if needed)
- **Python version** — `python --version`
- **Expected vs actual output** — what you expected the report/stdout to contain, and what
  actually appeared
- **Stack trace** — if the tool crashed, the full traceback

If the bug involves a specific log pattern (e.g. a parser silently dropping events), attach
or inline a minimal reproducing log snippet — even 5–10 lines that trigger the issue.

---

## License

By contributing you agree that your changes will be released under the project's
[MIT License](LICENSE).
