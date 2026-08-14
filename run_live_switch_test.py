"""Live end-to-end validation of the SWITCH+TERMINATE path in
log_analyzer_soc_pipeline_orchestrated.

This script does NOT run the full log-parsing pipeline. Instead it acts as a
synthetic worker: it starts the workflow, polls for each SIMPLE task, and
completes each one with zero-incident output. The SWITCH and TERMINATE tasks
execute server-side (they are Conductor built-in system tasks with no Python
worker counterpart), so this proves that Conductor's real JS expression evaluator
routes the workflow to TERMINATE when incident_count == 0.

Usage:
    source ~/.orkes_env
    python3 run_live_switch_test.py

Expected console output:
    Registered log_analyzer_soc_pipeline_orchestrated v1
    Started workflow: <run-id>  ->  <ui-url>
    Completed task detect_brute_force (ref=bf_ref)
    Completed task detect_port_scan   (ref=ps_ref)
    Completed task detect_404_flood   (ref=flood_ref)
    Completed task ml_score           (ref=ml_ref)
    Completed task join_incidents     (ref=join_ref)
    ... polling for SWITCH+TERMINATE ...
    PASS  Workflow <run-id> reached status COMPLETED
    PASS  Termination reason: no_threats_detected
    Live Conductor URL: https://developer.orkescloud.com/execution/<run-id>
"""
from __future__ import annotations

import os
import sys
import time

# ---------------------------------------------------------------------------
# Env guard — must be sourced before running
# ---------------------------------------------------------------------------
if not os.environ.get("CONDUCTOR_SERVER_URL"):
    sys.exit(
        "CONDUCTOR_SERVER_URL not set.\n"
        "Run:  source ~/.orkes_env && python3 run_live_switch_test.py"
    )

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from conductor.client.configuration.configuration import Configuration
from conductor.client.orkes.orkes_task_client import OrkesTaskClient
from conductor.client.orkes.orkes_workflow_client import OrkesWorkflowClient

import register_conductor  # run registration logic

# ---------------------------------------------------------------------------
# Task output fixtures: zero incidents from every detector
# ---------------------------------------------------------------------------
# Zero-incident output fixture keyed by task reference name.
_TASK_REF_OUTPUT: dict[str, dict] = {
    "bf_ref":    {"incidents": [], "log_format": "ssh", "count": 0},
    "ps_ref":    {"incidents": [], "log_format": "ssh", "count": 0},
    "flood_ref": {"incidents": [], "log_format": "ssh", "count": 0},
    "ml_ref":    {"anomaly_scores": {}, "events": 0},
    "join_ref":  {
        "incidents":      [],
        "anomaly_scores": {},
        "counts":         {"incidents": 0, "events": 0},
    },
}

# The 4 fork branches can be completed in any order (they are parallel).
# join_ref only becomes available after all 4 are done and the JOIN fires.
_FORK_REFS  = ["bf_ref", "ps_ref", "flood_ref", "ml_ref"]

_WF_TIMEOUT_S    = 90
_POLL_INTERVAL_S = 1


def _wait_for_ref(wf_client: OrkesWorkflowClient, run_id: str, ref_name: str, deadline: float) -> bool:
    """Return True once the task with *ref_name* appears in the workflow's task list."""
    while time.monotonic() < deadline:
        wf = wf_client.get_workflow(run_id, include_tasks=True)
        if any(t.reference_task_name == ref_name for t in wf.tasks):
            return True
        time.sleep(_POLL_INTERVAL_S)
    return False


def _complete_by_ref(task_client: OrkesTaskClient, run_id: str, ref_name: str) -> None:
    """Complete a specific task in *run_id* by reference name with zero-incident output.

    update_task_sync targets the exact workflow run (no polling race) and passes
    output_data directly as the body — update_task_by_ref_name wraps it in
    {"result": ...} which breaks the ${join_ref.output.counts.incidents} expression.
    """
    task_client.update_task_sync(
        workflow_id=run_id,
        task_ref_name=ref_name,
        status="COMPLETED",
        output=_TASK_REF_OUTPUT[ref_name],
    )
    print(f"  Completed ref={ref_name}")


def main() -> None:
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
            "log_path":    "/dev/null",
            "soc_url":     "http://localhost:8000/api/alerts",
            "soc_api_key": "test-key",
        },
    )
    ui_url = f"https://developer.orkescloud.com/execution/{run_id}"
    print(f"Started workflow: {run_id}")
    print(f"  UI → {ui_url}")

    deadline = time.monotonic() + _WF_TIMEOUT_S

    # ── 3. Complete the 4 fork-branch detector tasks (parallel, any order) ───
    print("Completing fork-branch tasks …")
    for ref in _FORK_REFS:
        if not _wait_for_ref(wf_client, run_id, ref, deadline):
            sys.exit(f"FAIL  Task ref={ref} never appeared in workflow.")
        _complete_by_ref(task_client, run_id, ref)

    # ── 4. Wait for the JOIN to fire, then complete join_incidents ────────────
    print("Waiting for JOIN + join_incidents …")
    if not _wait_for_ref(wf_client, run_id, "join_ref", deadline):
        sys.exit("FAIL  join_ref never appeared after fork tasks completed.")
    _complete_by_ref(task_client, run_id, "join_ref")

    # ── 4. Poll workflow until terminal state (SWITCH + TERMINATE fire server-side)
    print("Waiting for SWITCH+TERMINATE to execute server-side …")
    deadline = time.monotonic() + _WF_TIMEOUT_S
    wf = None
    while time.monotonic() < deadline:
        wf = wf_client.get_workflow(run_id, include_tasks=True)
        if wf.status in ("COMPLETED", "FAILED", "TERMINATED", "TIMED_OUT"):
            break
        print(f"  … workflow status: {wf.status}")
        time.sleep(_POLL_INTERVAL_S)
    else:
        sys.exit(f"FAIL  Workflow did not reach a terminal state within {_WF_TIMEOUT_S}s.")

    # ── 5. Assertions ─────────────────────────────────────────────────────────
    assert wf.status == "COMPLETED", f"FAIL  Expected COMPLETED, got {wf.status}"
    print(f"PASS  Workflow {run_id[:16]}… reached status COMPLETED")

    # Find the TERMINATE task and read its terminationReason from the workflow output.
    terminate_tasks = [t for t in wf.tasks if t.task_type == "TERMINATE"]
    assert terminate_tasks, "FAIL  No TERMINATE task found in workflow execution"

    reason = (wf.output or {}).get("terminationReason", "")
    if not reason:
        # Fall back: look in the terminate task's input params
        reason = (terminate_tasks[0].input_data or {}).get("terminationReason", "")

    assert reason == "no_threats_detected", (
        f"FAIL  Expected terminationReason='no_threats_detected', got {reason!r}"
    )
    print(f"PASS  Termination reason: {reason}")

    # Confirm enrich_geoip was never scheduled.
    enrich_tasks = [t for t in wf.tasks if t.reference_task_name == "enrich_ref"]
    assert not enrich_tasks, (
        f"FAIL  enrich_geoip was scheduled despite zero incidents: {enrich_tasks}"
    )
    print("PASS  enrich_geoip was never scheduled (confirmed server-side)")

    print(f"\nLive Conductor URL:\n  {ui_url}")


if __name__ == "__main__":
    main()
