"""Live end-to-end validation of the Phase 3 WAIT human-approval gate in
log_analyzer_soc_pipeline_orchestrated v1.

Runs two scenarios in sequence:
  A. CRITICAL incident → workflow pauses at approval_wait_ref → approve via
     update_task_sync → workflow proceeds to push_to_dashboard → COMPLETED.
  B. HIGH incident    → severity_route_switch takes the non_critical path →
     push_to_dashboard runs immediately (no WAIT) → COMPLETED.

This validates the real Conductor JS expression
    $.incidents.some(function(i) { return i.severity === 'CRITICAL'; })
        ? 'critical' : 'non_critical'
on the Orkes server — the same thing Phase 1 did for the SWITCH+TERMINATE JS
expression.  A Python-only test cannot catch an expression that evaluates
correctly in Python but fails in the Conductor JS engine.

Usage:
    source ~/.orkes_env
    python3 run_live_phase3_test.py

Expected output (abbreviated):
    === Scenario A: CRITICAL incident — WAIT gate ===
    Started workflow: <run-id>  ->  <ui-url>
    SWITCH routed to has_incidents path (enrich_geoip is scheduled)
    All 5 output-fork refs scheduled
    PASS  Workflow paused at approval_wait_ref (status=RUNNING)
    Releasing approval gate via update_task_sync ...
    PASS  Workflow <run-id> reached status COMPLETED
    === Scenario B: HIGH incident — non_critical path ===
    PASS  severity_route_switch did NOT schedule approval_wait_ref (non-critical path confirmed)
    PASS  Workflow <run-id> reached status COMPLETED
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
# Common fixtures
# ---------------------------------------------------------------------------

_CRITICAL_INCIDENT = {
    "incident_type": "brute_force",
    "source_ip":     "198.51.100.1",
    "event_count":   900,
    "severity":      "CRITICAL",
    "mitre":         {"id": "T1110.001", "name": "Brute Force: Password Guessing"},
}

_HIGH_INCIDENT = {
    "incident_type": "port_scan",
    "source_ip":     "198.51.100.2",
    "event_count":   300,
    "severity":      "HIGH",
    "mitre":         {"id": "T1046", "name": "Network Service Discovery"},
}


def _make_task_outputs(incident: dict) -> dict[str, dict]:
    enriched = {**incident, "geo": {"country": "US", "city": "Atlanta"}}
    return {
        "bf_ref":    {"incidents": [incident] if incident.get("incident_type") == "brute_force" else [], "log_format": "ssh", "count": 1 if incident.get("incident_type") == "brute_force" else 0},
        "ps_ref":    {"incidents": [incident] if incident.get("incident_type") == "port_scan"   else [], "log_format": "ssh", "count": 1 if incident.get("incident_type") == "port_scan"   else 0},
        "flood_ref": {"incidents": [], "log_format": "web", "count": 0},
        "ml_ref":    {"anomaly_scores": {incident["source_ip"]: 0.88}, "events": 500},
        "join_ref": {
            "incidents":      [incident],
            "anomaly_scores": {incident["source_ip"]: 0.88},
            "counts":         {"incidents": 1, "events": 500},
        },
        "enrich_ref": {
            "incidents":      [enriched],
            "anomaly_scores": {incident["source_ip"]: 0.88},
        },
        "summary_ref": {"summary": f"SOC: one {incident['severity']} {incident['incident_type']} incident."},
        "agent_ref":   {"report": None, "note": "ANTHROPIC_API_KEY unset or no content"},
        "sigma_ref":   {"files": [], "count": 0, "note": "ANTHROPIC_API_KEY unset"},
        "es_ref":      {"indexed": 0, "note": "es_host not configured"},
        "gcs_ref":     {"uploaded": False, "note": "gcs_bucket not configured"},
        "push_ref":    {"pushed": 1, "errors": []},
    }


_DETECT_FORK_REFS  = ["bf_ref", "ps_ref", "flood_ref", "ml_ref"]
_OUTPUT_FORK_REFS  = ["summary_ref", "agent_ref", "sigma_ref", "es_ref", "gcs_ref"]
_WF_TIMEOUT_S      = 120
_POLL_INTERVAL_S   = 1


def _wait_for_ref(wf_client: OrkesWorkflowClient, run_id: str, ref: str, deadline: float) -> bool:
    while time.monotonic() < deadline:
        wf = wf_client.get_workflow(run_id, include_tasks=True)
        if any(t.reference_task_name == ref for t in wf.tasks):
            return True
        time.sleep(_POLL_INTERVAL_S)
    return False


def _complete(task_client: OrkesTaskClient, run_id: str, ref: str, outputs: dict) -> None:
    task_client.update_task_sync(
        workflow_id=run_id,
        task_ref_name=ref,
        status="COMPLETED",
        output=outputs[ref],
    )


def _run_pipeline_up_to_severity_switch(
    wf_client: OrkesWorkflowClient,
    task_client: OrkesTaskClient,
    run_id: str,
    outputs: dict,
    deadline: float,
) -> None:
    """Complete all tasks from detection fork through the output FORK_JOIN."""
    for ref in _DETECT_FORK_REFS:
        if not _wait_for_ref(wf_client, run_id, ref, deadline):
            sys.exit(f"FAIL  {ref} never appeared.")
        _complete(task_client, run_id, ref, outputs)

    if not _wait_for_ref(wf_client, run_id, "join_ref", deadline):
        sys.exit("FAIL  join_ref never appeared.")
    _complete(task_client, run_id, "join_ref", outputs)

    if not _wait_for_ref(wf_client, run_id, "enrich_ref", deadline):
        sys.exit("FAIL  enrich_ref never appeared — SWITCH may have terminated.")
    print("  SWITCH routed to has_incidents path (enrich_geoip is scheduled)")
    _complete(task_client, run_id, "enrich_ref", outputs)

    for ref in _OUTPUT_FORK_REFS:
        if not _wait_for_ref(wf_client, run_id, ref, deadline):
            sys.exit(f"FAIL  Output fork ref={ref} never appeared.")
        _complete(task_client, run_id, ref, outputs)
    print("  All 5 output-fork refs scheduled and completed")


def _wait_terminal(wf_client: OrkesWorkflowClient, run_id: str, deadline: float):
    while time.monotonic() < deadline:
        wf = wf_client.get_workflow(run_id, include_tasks=True)
        if wf.status in ("COMPLETED", "FAILED", "TERMINATED", "TIMED_OUT"):
            return wf
        time.sleep(_POLL_INTERVAL_S)
    sys.exit(f"FAIL  Workflow {run_id} did not reach terminal state in time.")


# ---------------------------------------------------------------------------
# Scenario A: CRITICAL → WAIT gate → approve → COMPLETED
# ---------------------------------------------------------------------------

def scenario_a(wf_client, task_client):
    print("\n=== Scenario A: CRITICAL incident — WAIT gate ===")
    outputs = _make_task_outputs(_CRITICAL_INCIDENT)
    run_id  = wf_client.start_workflow_by_name(
        name="log_analyzer_soc_pipeline_orchestrated", version=1,
        input={"log_path": "/tmp/test.log", "soc_url": "http://localhost:8000/api/alerts",
               "soc_api_key": "test-key", "es_host": "", "gcs_bucket": ""},
    )
    ui_url  = f"https://developer.orkescloud.com/execution/{run_id}"
    print(f"Started workflow: {run_id}")
    print(f"  UI → {ui_url}")
    deadline = time.monotonic() + _WF_TIMEOUT_S

    _run_pipeline_up_to_severity_switch(wf_client, task_client, run_id, outputs, deadline)

    # After output JOIN, severity_route_switch should fire and route to 'critical'.
    # The workflow must pause at the WAIT task (approval_wait_ref).
    print("  Waiting for severity_route_switch to fire and workflow to pause at WAIT ...")
    pause_deadline = time.monotonic() + 20
    wf = None
    while time.monotonic() < pause_deadline:
        wf = wf_client.get_workflow(run_id, include_tasks=True)
        has_wait = any(t.reference_task_name == "approval_wait_ref" for t in wf.tasks)
        if has_wait:
            break
        time.sleep(_POLL_INTERVAL_S)

    assert wf is not None and any(t.reference_task_name == "approval_wait_ref" for t in wf.tasks), (
        f"FAIL  approval_wait_ref never appeared in workflow tasks — "
        f"the severity SWITCH may not have routed to 'critical'. "
        f"Check the JS expression on the Orkes server."
    )

    # Workflow must still be RUNNING (paused at WAIT), not COMPLETED.
    wf = wf_client.get_workflow(run_id, include_tasks=True)
    assert wf.status == "RUNNING", (
        f"FAIL  Expected workflow to be RUNNING (paused at WAIT), got {wf.status!r}"
    )
    print(f"PASS  Workflow paused at approval_wait_ref (status={wf.status})")
    print(f"      Live execution (paused): {ui_url}")

    # Release the WAIT gate — this is what the SOC-Dashboard endpoint does.
    print("  Releasing approval gate via update_task_sync ...")
    task_client.update_task_sync(
        workflow_id=run_id,
        task_ref_name="approval_wait_ref",
        status="COMPLETED",
        output={"approved_by": "live-test-script", "note": "Phase 3 automated validation"},
    )

    # After approval, push_to_dashboard should complete and the workflow should reach COMPLETED.
    if not _wait_for_ref(wf_client, run_id, "push_ref", time.monotonic() + _WF_TIMEOUT_S):
        sys.exit("FAIL  push_ref never appeared after WAIT was released.")
    _complete(task_client, run_id, "push_ref", outputs)

    wf = _wait_terminal(wf_client, run_id, time.monotonic() + _WF_TIMEOUT_S)
    assert wf.status == "COMPLETED", f"FAIL  Expected COMPLETED, got {wf.status}"
    print(f"PASS  Workflow {run_id[:16]}… reached status COMPLETED")
    print(f"      Live execution (completed): {ui_url}")
    return ui_url, run_id


# ---------------------------------------------------------------------------
# Scenario B: HIGH (non-critical) → no WAIT → COMPLETED directly
# ---------------------------------------------------------------------------

def scenario_b(wf_client, task_client):
    print("\n=== Scenario B: HIGH incident — non_critical path (no WAIT) ===")
    outputs  = _make_task_outputs(_HIGH_INCIDENT)
    run_id   = wf_client.start_workflow_by_name(
        name="log_analyzer_soc_pipeline_orchestrated", version=1,
        input={"log_path": "/tmp/test.log", "soc_url": "http://localhost:8000/api/alerts",
               "soc_api_key": "test-key", "es_host": "", "gcs_bucket": ""},
    )
    ui_url   = f"https://developer.orkescloud.com/execution/{run_id}"
    print(f"Started workflow: {run_id}")
    print(f"  UI → {ui_url}")
    deadline = time.monotonic() + _WF_TIMEOUT_S

    _run_pipeline_up_to_severity_switch(wf_client, task_client, run_id, outputs, deadline)

    # For non-critical: push_to_dashboard fires immediately after the SWITCH.
    if not _wait_for_ref(wf_client, run_id, "push_ref", time.monotonic() + 20):
        sys.exit("FAIL  push_ref never appeared after output JOIN on non-critical path.")
    _complete(task_client, run_id, "push_ref", outputs)

    wf = _wait_terminal(wf_client, run_id, time.monotonic() + _WF_TIMEOUT_S)
    assert wf.status == "COMPLETED", f"FAIL  Expected COMPLETED, got {wf.status}"

    # Confirm approval_wait_ref was never scheduled.
    wait_tasks = [t for t in wf.tasks if t.reference_task_name == "approval_wait_ref"]
    assert not wait_tasks, (
        f"FAIL  approval_wait_ref was scheduled on the non-critical path: {wait_tasks}"
    )
    print("PASS  severity_route_switch did NOT schedule approval_wait_ref (non-critical path confirmed)")
    print(f"PASS  Workflow {run_id[:16]}… reached status COMPLETED")
    print(f"      Live execution: {ui_url}")
    return ui_url, run_id


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> None:
    if not os.environ.get("CONDUCTOR_SERVER_URL"):
        sys.exit(
            "CONDUCTOR_SERVER_URL not set.\n"
            "Run:  source ~/.orkes_env && python3 run_live_phase3_test.py"
        )

    config      = Configuration()
    wf_client   = OrkesWorkflowClient(config)
    task_client = OrkesTaskClient(config)

    print("Registering log_analyzer_soc_pipeline_orchestrated …")
    register_conductor.main()

    url_a, _ = scenario_a(wf_client, task_client)
    url_b, _ = scenario_b(wf_client, task_client)

    print("\n=== All Phase 3 assertions passed ===")
    print(f"Scenario A (CRITICAL + WAIT + approve): {url_a}")
    print(f"Scenario B (HIGH, no WAIT):             {url_b}")


if __name__ == "__main__":
    main()
