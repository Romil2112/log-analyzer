# Orkes Conductor orchestration: log-analyzer → SOC-Dashboard

This wires the log-analyzer detection pipeline and the SOC-Dashboard triage UI into one
durable, retryable, observable workflow on [Orkes Conductor](https://orkes.io). Conductor
hosts the orchestration control plane + UI; the worker code runs on your machine and polls
Conductor for tasks.

```
                 ┌─────────────── Orkes Conductor (cloud control plane + UI) ───────────────┐
                 │   workflow: log_analyzer_soc_pipeline                                     │
                 │   analyze_log ──► generate_claude_summary ──► push_to_dashboard           │
                 └───────▲───────────────────▲──────────────────────────▲───────────────────┘
                         │ poll/complete      │                          │
                 ┌───────┴────────────────────┴──────────────────────────┴───────┐
                 │  start_workers.py  (this repo, runs locally, polls Conductor)   │
                 │  parse→detect→enrich→ML   Claude API      HTTP POST /api/alerts │
                 └────────────────────────────────────────────────┬───────────────┘
                                                                   ▼
                                                        SOC-Dashboard /api/alerts
```

## Files

| File | Purpose |
|------|---------|
| `conductor_workers.py` | Three `@worker_task` adapters wrapping existing pipeline functions (no detection logic changed). |
| `start_workers.py` | Launches the workers (thread-per-worker; see the macOS note below). |
| `register_conductor.py` | One-time registration of the task defs + workflow on the server. |
| `conductor_workflow.json` | The workflow definition (also importable via the Orkes UI). |
| `requirements-conductor.txt` | The `conductor-python` SDK dependency. |

## Worker stages

1. **`analyze_log(log_path, log_format="auto", enrich_ip=True, run_ml=True)`** — parse →
   detect (brute-force / port-scan / 404-flood) → severity+MITRE → optional GeoIP/threat-intel
   → optional IsolationForest scoring. Returns a JSON-safe list of `incidents` (a few hundred
   dicts) plus `counts` and `anomaly_scores`. Raw events (which carry `datetime`s and can be
   hundreds of thousands of rows) stay inside this worker and never cross a task boundary.
2. **`generate_claude_summary(incidents, anomaly_scores)`** — a 3-sentence SOC exec summary via
   the Claude API. Returns `summary=None` (no error) if `ANTHROPIC_API_KEY` is unset.
3. **`push_to_dashboard(incidents, soc_url, soc_api_key)`** — POSTs each incident to
   SOC-Dashboard's `/api/alerts` (needs the `X-API-Key` matching SOC's `ALERTS_API_KEY`).

## Setup

```bash
cd log-analyzer
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt -r requirements-conductor.txt

# Orkes Developer Edition credentials (Settings → API Keys in the Orkes UI)
export CONDUCTOR_SERVER_URL="https://developer.orkescloud.com/api"
export CONDUCTOR_AUTH_KEY="<your-key-id>"
export CONDUCTOR_AUTH_SECRET="<your-key-secret>"

# Optional
export ANTHROPIC_API_KEY="<claude-key>"     # enables the summary stage
```

## Run

```bash
# 1. Register task defs + workflow on the server (idempotent, one time)
./.venv/bin/python register_conductor.py

# 2. Start SOC-Dashboard (separate terminal, so the push has a target)
cd ../SOC-Dashboard
FLASK_SECRET_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))') \
ALERTS_API_KEY=demo-soc-key \
DATABASE_URL=postgresql://localhost/soc_dashboard \
PORT=8000 ./.venv/bin/python app.py

# 3. Start the workers (they poll Conductor until Ctrl-C)
cd ../log-analyzer
./.venv/bin/python start_workers.py

# 4. Trigger a run — from the Orkes UI (Run Workflow → log_analyzer_soc_pipeline) with input:
#      { "log_path": "/abs/path/to/test_auth.log",
#        "soc_url": "http://localhost:8000/api/alerts",
#        "soc_api_key": "demo-soc-key" }
#    …or from Python:
./.venv/bin/python - <<'PY'
import os
from conductor.client.configuration.configuration import Configuration
from conductor.client.orkes.orkes_workflow_client import OrkesWorkflowClient
from conductor.client.http.models.start_workflow_request import StartWorkflowRequest
wf = OrkesWorkflowClient(Configuration())
run = wf.execute_workflow(StartWorkflowRequest(
    name="log_analyzer_soc_pipeline", version=1,
    input={"log_path": os.path.abspath("test_auth.log"),
           "soc_url": "http://localhost:8000/api/alerts",
           "soc_api_key": "demo-soc-key"}), wait_for_seconds=60)
print(run.status, run.output)
PY
```

Watch the run flow through the three stages in the Orkes UI; the pushed incidents appear in
the SOC-Dashboard open-alerts queue.

## Gotchas discovered while building this

- **macOS + Python 3.14 → use the thread runner.** The SDK's default `TaskHandler` spawns
  each worker in its own OS process; on macOS + Python 3.14 those subprocesses segfault
  (exit code -11) on the first poll. `start_workers.py` runs each worker in a *thread* via
  `TaskRunner` instead — same polling behavior, one stable process.
- **Worker type hints must be real, non-parameterized types.** The SDK deserializes task
  inputs from the function's annotations. Do **not** use `from __future__ import annotations`
  (it stringifies them and breaks `isinstance`). A **list** parameter must be typed
  `List[dict]` (the SDK calls `typing.get_args(annotation)[0]`, so bare `list` throws
  `IndexError`); scalars/dicts are fine bare; avoid `dict | None` (use `dict` + `None` default).
- **Keep big/`datetime` payloads inside a worker.** Conductor serializes every task
  input/output to JSON. Parsed events aren't JSON-safe (datetimes) and can be huge, so only
  the small incident list crosses task boundaries, with its datetimes converted to ISO strings.
- **DB is optional in the workflow.** `analyze_log` does not write to Postgres; the CLI's
  `--no-db` DB persistence path is separate. The workflow's persistence is the SOC push.
