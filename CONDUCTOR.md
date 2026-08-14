# Orkes Conductor orchestration: log-analyzer → SOC-Dashboard

This wires the log-analyzer detection pipeline and the SOC-Dashboard triage UI into one
durable, retryable, observable workflow on [Orkes Conductor](https://orkes.io). Conductor
hosts the orchestration control plane + UI; the worker code runs on your machine and polls
Conductor for tasks.

```
        ┌──────────────── Orkes Conductor (cloud control plane + UI) ────────────────┐
        │  workflow: log_analyzer_soc_pipeline  (v5, fork/join + enrich + provenance) │
        │                                                                             │
        │            ┌─ detect_brute_force ─┐                                         │
        │   (FORK) ──┼─ detect_port_scan  ──┼── (JOIN) ─► join_incidents              │
        │            ├─ detect_404_flood  ──┤                 │                       │
        │            └─ ml_score          ──┘                 ▼                       │
        │                                          enrich_geoip (threat-intel+GeoIP)  │
        │                                                     │                       │
        │                                                     ▼                       │
        │                              generate_claude_summary ─► push_to_dashboard   │
        └───────▲────────────────────────────────────────────────────▲───────────────┘
                │ poll/complete                                        │
        ┌───────┴────────────────────────────────────────────────────┴───────┐
        │  start_workers.py  (this repo, runs locally, polls Conductor)        │
        └─────────────────────────────────────────────────┬───────────────────┘
                                                           ▼
                                                SOC-Dashboard /api/alerts
```

Three versions are registered on the server. **v1** runs the whole detection pipeline
inside a single `analyze_log` task (a straight three-node line). **v2** forks the three
detectors and the ML scorer into four parallel tasks and joins them — a real DAG with
independently retryable, observable stages. **v3** pulls threat-intel + GeoIP enrichment
out of the join into its own `enrich_geoip` stage, so `join_incidents` only merges and
tags severity/MITRE (cheap, local), and the enrichment lookups are separately timed and
retryable. **v4** enriches each incident dict in place inside `enrich_geoip` — merging the
per-IP anomaly score and a flat `mitre_id` so one incident carries severity, MITRE, GeoIP,
threat-intel, and anomaly score together — and returns aggregate stats (known-bad count,
countries, scored) so the task panel shows substance. **v5** attaches run provenance to
every pushed alert — the workflow id (wired from `${workflow.workflowId}`) plus a
best-effort per-task timing blob that `push_to_dashboard` reads back from Conductor — so
the SOC-Dashboard can trace each alert to the run that produced it and how long each stage
took. Each fork branch re-parses the log locally so only small incident lists (never the
raw events) cross a task boundary.

## A live run

Below is a real **v3** run of `log_analyzer_soc_pipeline` against a 10,000-event SSH log.
The three detectors and the ML scorer run in parallel off the fork; the join merges and
tags them into six incidents; `enrich_geoip` adds threat-intel + GeoIP as its own stage;
Claude writes an executive summary; and the six incidents are pushed to the SOC-Dashboard —
the whole DAG completing in about five seconds.

![Conductor v3 fork/join + enrich execution](docs/conductor_dag.png)

End to end, from the Conductor run to the incidents landing in the analyst's queue:

![Pipeline walkthrough: Conductor run to SOC triage](docs/pipeline_demo.gif)

With `ANTHROPIC_API_KEY` set, `generate_claude_summary` returns a real executive summary.
A representative excerpt from the run above:

> Our organization detected five distinct attack sources conducting reconnaissance and
> credential compromise attempts, with the most severe threat originating from 10.99.99.99,
> which executed 783 brute-force login attempts (MITRE T1110.001 - Credential Stuffing)…
> Recommended immediate actions: (1) block all identified IPs at the firewall and implement
> rate-limiting on authentication endpoints, (2) enforce MFA across all accounts…

The stage is still optional: it returns `null` — without failing the workflow — when the
key is unset *or* invalid, so the downstream SOC push always runs.

By the time an incident reaches `push_to_dashboard` it carries every computed field in one
place — as of v4, severity, MITRE (nested + flat `mitre_id`), GeoIP, threat-intel, and the
per-IP anomaly score together:

```json
{
  "incident_type": "brute_force",
  "source_ip": "10.99.99.99",
  "severity": "CRITICAL",
  "mitre_id": "T1110.001",
  "mitre": { "id": "T1110.001", "name": "Brute Force: Password Guessing", "tactic": "Credential Access" },
  "country": "Unknown",
  "known_bad": false,
  "anomaly_score": 1.0,
  "event_count": 783
}
```

`anomaly_score` is `null` when the ML stage did not score that IP — honest, not an error.
`enrich_geoip` also returns aggregate stats (`enriched`, `known_bad_count`, `countries`,
`scored`) so its Orkes task panel shows a rollup rather than just the incident list.

## Fan-out across log sources

`log_analyzer_multi_source` (v1) is a parent workflow that runs the v4 pipeline as a
sub-workflow once per log source, in parallel, then joins. One manual trigger fans out to
three independent executions — an SSH log, a web log, and a mixed log — so all three
detector types (brute-force, port-scan, 404-flood) are exercised across the sources, and
each source's incidents are pushed to the SOC-Dashboard by its own sub-workflow.

![Multi-source fan-out parent execution](docs/multisource_fanout.png)

Each branch is a Conductor `SUB_WORKFLOW` task pointing at `log_analyzer_soc_pipeline`
version 4; the `JOIN` waits for all three before the parent completes. No new workers are
needed — the sub-workflows reuse the v4 workers. Register it alongside the pipeline with
`register_conductor.py`, then trigger it with three `log_*` inputs plus `soc_url` /
`soc_api_key`.

### Scheduling (not built)

Orkes can also run a workflow on a cron-style schedule via its Scheduler, which would give a
history of runs over time. This is intentionally **not** wired up here: a recurring schedule
fires unattended, and since each firing runs the full pipeline it would make real Claude API
calls and push alerts to the SOC on a timer whether or not anyone is watching — recurring
cost with little value for a one-shot live demo. If it were added, it would use the SDK's
`OrkesSchedulerClient` (a `save_schedule` call with a cron expression targeting
`log_analyzer_multi_source`) and be torn down with `delete_schedule(name)` (or paused) so
nothing runs unattended. The manual fan-out above is the substantive, on-demand half.

## `log_analyzer_soc_pipeline_orchestrated`

`log_analyzer_soc_pipeline_orchestrated` is a second workflow registered on the same Conductor
server. It extends the detection + push pipeline with three enhancements — a short-circuit
SWITCH, a parallel AI/export output stage, and a human-approval gate for critical findings —
built incrementally across three phases.

```
        ┌──────────────────── Orkes Conductor ───────────────────────────────────────────┐
        │  log_analyzer_soc_pipeline_orchestrated (v1)                                    │
        │                                                                                 │
        │           ┌─ detect_brute_force ─┐                                              │
        │  (FORK) ──┼─ detect_port_scan  ──┼── (JOIN) ─► join_incidents                   │
        │           ├─ detect_404_flood  ──┤                   │                          │
        │           └─ ml_score          ──┘                   ▼                          │
        │                                        SWITCH: any incidents?                   │
        │                                          YES ──► enrich_geoip                   │
        │                                          NO  ──► TERMINATE                      │
        │                                                       │                         │
        │                    ┌─ generate_claude_summary ──┐     │                         │
        │         (FORK) ────┼─ run_ai_agent             ─┼── (JOIN)                      │
        │                    ├─ generate_sigma_rules     ─┤      │                        │
        │                    ├─ elasticsearch_ingest     ─┤      ▼                        │
        │                    └─ gcs_upload_report        ─┘  SWITCH: any CRITICAL?        │
        │                                                    CRITICAL ──► WAIT (4 hr)     │
        │                                                                    │            │
        │                                               non-critical / approved ▼         │
        │                                                   push_to_dashboard             │
        └─────────────────────────────────────────────────────────────────────────────────┘
```

### Phase 1 — Incident count SWITCH + TERMINATE

After `join_incidents`, a JavaScript SWITCH checks whether the incident list is non-empty. An
empty result short-circuits the workflow (TERMINATED — no API calls, no SOC push); a non-empty
result routes to `enrich_geoip`. The expression runs on the Orkes server:

```javascript
$.incidents.length > 0 ? 'has_incidents' : 'no_incidents'
```

This avoids unnecessary Claude API calls and SOC pushes when a log produces zero detections —
a normal outcome for well-behaved hosts.

### Phase 2 — Parallel AI / export output FORK_JOIN

After `enrich_geoip`, the workflow fans out into five concurrent branches instead of calling
`generate_claude_summary` alone:

| Branch ref | Worker | Wraps | Degrades when |
|---|---|---|---|
| `summary_ref` | `generate_claude_summary` | `ai_summary.ai_summary` | `ANTHROPIC_API_KEY` unset |
| `agent_ref` | `run_ai_agent` | `ai_agent.run_investigation` | `ANTHROPIC_API_KEY` unset |
| `sigma_ref` | `generate_sigma_rules` | `sigma_export.export_sigma_llm` | `ANTHROPIC_API_KEY` unset |
| `es_ref` | `elasticsearch_ingest` | `es_ingest` bulk helpers | `es_host` input empty |
| `gcs_ref` | `gcs_upload_report` | `log_analyzer._upload_to_gcs` | `gcs_bucket` input empty |

All five run concurrently and return a `note` field (not an error) when their external dependency is
absent, so the JOIN always fires and `push_to_dashboard` always runs. No missing API key blocks
the pipeline — every branch degrades gracefully to a no-op.

### Phase 3 — Severity SWITCH + human-approval WAIT gate

After the output JOIN, a second SWITCH checks whether any enriched incident has
`severity == "CRITICAL"` using a JS `Array.prototype.some` expression validated live on the
Orkes server before being trusted:

```javascript
$.incidents.some(function(i) { return i.severity === 'CRITICAL'; }) ? 'critical' : 'non_critical'
```

- **`critical` path:** routes to `approval_wait_ref`, a WAIT task with `timeoutSeconds=14400`
  (4 hours) and `timeoutPolicy=ALERT_ONLY`. The workflow pauses here — `push_to_dashboard`
  does not run — until an analyst releases the gate.
- **`non_critical` path:** empty `decisionCase`; the workflow falls through directly to
  `push_to_dashboard` with no gate.

`ALERT_ONLY` means the server logs an alert if the wait exceeds 4 hours but does not fail or
terminate the workflow — it keeps waiting until explicitly approved or the run is cancelled.

#### Releasing the WAIT gate

`POST /api/alerts/<workflow_run_id>/approve` in SOC-Dashboard (behind `@login_required`,
requires `CONDUCTOR_SERVER_URL` set) calls `OrkesTaskClient.update_task_sync` to mark
`approval_wait_ref` COMPLETED:

```bash
curl -X POST http://localhost:8000/api/alerts/<run-id>/approve \
  -H "Content-Type: application/json" \
  -b "session=..." \
  -d '{"note": "elevated false-positive rate from scanning tool — confirmed not an intrusion"}'
# → {"workflow_run_id": "...", "approved_by": "alice", "status": "released"}
```

After the call returns, `push_to_dashboard` runs and the workflow reaches COMPLETED.

Live execution — Scenario A (CRITICAL → paused at WAIT → approved → COMPLETED):
`https://developer.orkescloud.com/execution/t9ore82eff02-9822-11f1-ae0f-324491a4c010`

Live execution — Scenario B (HIGH → `non_critical` path → no WAIT → COMPLETED):
`https://developer.orkescloud.com/execution/t9oreaa78ce3-9822-11f1-a633-f2fc4b0e8ae3`

## Files

| File | Purpose |
|------|---------|
| `conductor_workers.py` | `@worker_task` adapters for the base pipeline: `analyze_log` (v1), plus `detect_brute_force` / `detect_port_scan` / `detect_404_flood` / `ml_score` / `join_incidents` (v2 fork/join), `enrich_geoip` (v3/v4), `generate_claude_summary`, and `push_to_dashboard`. |
| `conductor_orchestrated_workers.py` | `@worker_task` adapters for `log_analyzer_soc_pipeline_orchestrated`: `run_ai_agent`, `generate_sigma_rules`, `elasticsearch_ingest`, `gcs_upload_report` (Phase 2), plus `_switch_severity_route()` (Phase 3 Python mirror of the JS SWITCH expression for unit testing). |
| `start_workers.py` | Launches all workers (thread-per-worker; see the macOS note below). |
| `register_conductor.py` | One-time registration of task defs + both workflows on the server. Handles inline `taskDefinition` blocks in workflow JSON (used by the WAIT task to set `timeoutSeconds=14400` and `timeoutPolicy=ALERT_ONLY`). |
| `conductor_workflow.json` | The `log_analyzer_soc_pipeline` pipeline definition (v4; also importable via the Orkes UI). |
| `conductor_orchestrated.json` | The `log_analyzer_soc_pipeline_orchestrated` workflow definition — two FORK_JOINs, two SWITCHes, and an inline WAIT task definition. |
| `conductor_multi_source.json` | The `log_analyzer_multi_source` parent fan-out workflow (SUB_WORKFLOW per log source). |
| `requirements-conductor.txt` | The `conductor-python` SDK dependency (optional; not installed in CI). |

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
