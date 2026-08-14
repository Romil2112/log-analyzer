"""Live end-to-end validation of the output FORK_JOIN in
log_analyzer_soc_pipeline_orchestrated v1 (Phase 2).

Acts as a synthetic worker: starts the workflow, completes all SIMPLE tasks with
realistic fixture data, then asserts the workflow reaches COMPLETED status and all
five output-fork branches were scheduled. Optional workers (run_ai_agent,
generate_sigma_rules, elasticsearch_ingest, gcs_upload_report) return graceful-
degradation outputs so the workflow succeeds even with no real API keys.

Usage:
    source ~/.orkes_env
    python3 run_live_phase2_test.py

Expected console output:
    Registered log_analyzer_soc_pipeline_orchestrated v1
    Started workflow: <run-id>  ->  <ui-url>
    Completed detect fork branches (4 tasks)
    Completed join_incidents (join_ref)
    SWITCH routed to has_incidents path
    Completed enrich_geoip (enrich_ref)
    Completed output fork branches (5 tasks)
    Completed push_to_dashboard (push_ref)
    PASS  Workflow <run-id> reached status COMPLETED
    PASS  All 5 output-fork branch refs were scheduled
    Live Conductor URL: https://developer.orkescloud.com/execution/<run-id>
"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from conductor.client.configuration.configuration import Configuration
from conductor.client.orkes.orkes_task_client import OrkesTaskClient
from conductor.client.orkes.orkes_workflow_client import OrkesWorkflowClient

import register_conductor

# ---------------------------------------------------------------------------
# Fixture data — one realistic incident so the SWITCH takes the has_incidents path
# ---------------------------------------------------------------------------

_SAMPLE_INCIDENT = {
    "incident_type": "brute_force",
    "source_ip": "198.51.100.1",
    "event_count": 120,
    "severity": "HIGH",
    "mitre": {"id": "T1110", "name": "Brute Force"},
}

_TASK_OUTPUT: dict[str, dict] = {
    "bf_ref": {
        "incidents": [_SAMPLE_INCIDENT],
        "log_format": "ssh",
        "count": 1,
    },
    "ps_ref":    {"incidents": [], "log_format": "ssh", "count": 0},
    "flood_ref": {"incidents": [], "log_format": "ssh", "count": 0},
    "ml_ref":    {"anomaly_scores": {"198.51.100.1": 0.92}, "events": 350},
    "join_ref": {
        "incidents": [_SAMPLE_INCIDENT],
        "anomaly_scores": {"198.51.100.1": 0.92},
        "counts": {"incidents": 1, "events": 350},
    },
    "enrich_ref": {
        "incidents": [{**_SAMPLE_INCIDENT, "geo": {"country": "US", "city": "Atlanta"}}],
        "anomaly_scores": {"198.51.100.1": 0.92},
    },
    # Output fork branches — graceful-degradation outputs (no real API keys needed)
    "summary_ref": {"summary": "SOC summary: 1 brute-force incident from 198.51.100.1 (HIGH)."},
    "agent_ref":   {"report": None, "note": "ANTHROPIC_API_KEY unset or no content"},
    "sigma_ref":   {"files": [], "count": 0, "note": "ANTHROPIC_API_KEY unset"},
    "es_ref":      {"indexed": 0, "note": "es_host not configured"},
    "gcs_ref":     {"uploaded": False, "note": "gcs_bucket not configured"},
    "push_ref":    {"pushed": 1, "errors": []},
}

_DETECT_FORK_REFS  = ["bf_ref", "ps_ref", "flood_ref", "ml_ref"]
_OUTPUT_FORK_REFS  = ["summary_ref", "agent_ref", "sigma_ref", "es_ref", "gcs_ref"]

_WF_TIMEOUT_S    = 120
_POLL_INTERVAL_S = 1


def _wait_for_ref(
    wf_client: OrkesWorkflowClient, run_id: str, ref_name: str, deadline: float
) -> bool:
    while time.monotonic() < deadline:
        wf = wf_client.get_workflow(run_id, include_tasks=True)
        if any(t.reference_task_name == ref_name for t in wf.tasks):
            return True
        time.sleep(_POLL_INTERVAL_S)
    return False


def _complete(task_client: OrkesTaskClient, run_id: str, ref: str, label: str = "") -> None:
    task_client.update_task_sync(
        workflow_id=run_id,
        task_ref_name=ref,
        status="COMPLETED",
        output=_TASK_OUTPUT[ref],
    )
    print(f"  Completed {label or ref}")


def main() -> None:
    if not os.environ.get("CONDUCTOR_SERVER_URL"):
        sys.exit(
            "CONDUCTOR_SERVER_URL not set.\n"
            "Run:  source ~/.orkes_env && python3 run_live_phase2_test.py"
        )

    config      = Configuration()
    wf_client   = OrkesWorkflowClient(config)
    task_client = OrkesTaskClient(config)

    # ── 1. Register (idempotent) ─────────────────────────────────────────────
    print("Registering log_analyzer_soc_pipeline_orchestrated …")
    register_conductor.main()

    # ── 2. Start workflow ────────────────────────────────────────────────────
    run_id = wf_client.start_workflow_by_name(
        name="log_analyzer_soc_pipeline_orchestrated",
        version=1,
        input={
            "log_path":    "/tmp/test_access.log",
            "soc_url":     "http://localhost:8000/api/alerts",
            "soc_api_key": "test-key",
            "es_host":     "",
            "gcs_bucket":  "",
        },
    )
    ui_url = f"https://developer.orkescloud.com/execution/{run_id}"
    print(f"Started workflow: {run_id}")
    print(f"  UI → {ui_url}")

    deadline = time.monotonic() + _WF_TIMEOUT_S

    # ── 3. Complete the 4 detection fork branches ─────────────────────────────
    print("Completing detect fork branches …")
    for ref in _DETECT_FORK_REFS:
        if not _wait_for_ref(wf_client, run_id, ref, deadline):
            sys.exit(f"FAIL  Task ref={ref} never appeared in workflow.")
        _complete(task_client, run_id, ref)
    print("  Completed detect fork branches (4 tasks)")

    # ── 4. Complete join_incidents (fires after detection JOIN) ───────────────
    print("Waiting for join_incidents …")
    if not _wait_for_ref(wf_client, run_id, "join_ref", deadline):
        sys.exit("FAIL  join_ref never appeared.")
    _complete(task_client, run_id, "join_ref", "join_incidents (join_ref)")

    # ── 5. Verify SWITCH routed to has_incidents, then complete enrich_geoip ──
    print("Waiting for enrich_geoip (confirms SWITCH took has_incidents path) …")
    if not _wait_for_ref(wf_client, run_id, "enrich_ref", deadline):
        sys.exit(
            "FAIL  enrich_ref never appeared — SWITCH may have terminated the workflow "
            "despite incident_count=1. Check the join_ref output."
        )
    print("  SWITCH routed to has_incidents path (enrich_geoip is scheduled)")
    _complete(task_client, run_id, "enrich_ref", "enrich_geoip (enrich_ref)")

    # ── 6. Complete the 5 output fork branches ────────────────────────────────
    print("Completing output fork branches (5 parallel tasks) …")
    for ref in _OUTPUT_FORK_REFS:
        if not _wait_for_ref(wf_client, run_id, ref, deadline):
            sys.exit(f"FAIL  Output fork ref={ref} never appeared.")
        _complete(task_client, run_id, ref)
    print("  Completed output fork branches (5 tasks)")

    # ── 7. Complete push_to_dashboard ────────────────────────────────────────
    print("Waiting for push_to_dashboard …")
    if not _wait_for_ref(wf_client, run_id, "push_ref", deadline):
        sys.exit("FAIL  push_ref never appeared after output JOIN.")
    _complete(task_client, run_id, "push_ref", "push_to_dashboard (push_ref)")

    # ── 8. Wait for terminal state ────────────────────────────────────────────
    print("Waiting for COMPLETED …")
    wf = None
    deadline2 = time.monotonic() + _WF_TIMEOUT_S
    while time.monotonic() < deadline2:
        wf = wf_client.get_workflow(run_id, include_tasks=True)
        if wf.status in ("COMPLETED", "FAILED", "TERMINATED", "TIMED_OUT"):
            break
        time.sleep(_POLL_INTERVAL_S)
    else:
        sys.exit(f"FAIL  Workflow did not reach terminal state within {_WF_TIMEOUT_S}s.")

    # ── 9. Assertions ─────────────────────────────────────────────────────────
    assert wf.status == "COMPLETED", f"FAIL  Expected COMPLETED, got {wf.status}"
    print(f"PASS  Workflow {run_id[:16]}… reached status COMPLETED")

    scheduled_refs = {t.reference_task_name for t in wf.tasks}
    missing = [r for r in _OUTPUT_FORK_REFS if r not in scheduled_refs]
    assert not missing, f"FAIL  Output fork refs never scheduled: {missing}"
    print(f"PASS  All 5 output-fork branch refs were scheduled: {_OUTPUT_FORK_REFS}")

    print(f"\nLive Conductor URL:\n  {ui_url}")


if __name__ == "__main__":
    main()
