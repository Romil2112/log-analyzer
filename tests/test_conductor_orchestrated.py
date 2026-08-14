"""Tests for log_analyzer_soc_pipeline_orchestrated — Phase 1: SWITCH + TERMINATE.

Covers:
  - join_incidents returns zero incident count for empty detector output
  - _switch_incident_route mirrors the Conductor JS expression correctly
  - enrich_geoip (and downstream stages) are never invoked on the zero-incident path
  - The workflow JSON has the required structural properties (SWITCH present,
    TERMINATE in the no_incidents case, enrich_geoip as a top-level task)
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from conductor_orchestrated_workers import (
    _simulate_orchestrated_pipeline,
    _switch_incident_route,
)
from conductor_workers import join_incidents

_REPO = Path(__file__).parent.parent

# ---------------------------------------------------------------------------
# Shared fixture
# ---------------------------------------------------------------------------

_SAMPLE_INCIDENT = {
    "incident_type": "brute_force",
    "source_ip": "10.0.0.1",
    "event_count": 50,
}

# ---------------------------------------------------------------------------
# join_incidents: zero count for empty detector output
# ---------------------------------------------------------------------------

def test_join_incidents_empty_lists_returns_zero_incident_count():
    result = join_incidents(brute=[], port=[], flood=[])
    assert result["counts"]["incidents"] == 0


def test_join_incidents_empty_lists_returns_zero_event_count():
    result = join_incidents(brute=[], port=[], flood=[], events=0)
    assert result["counts"]["events"] == 0


def test_join_incidents_single_incident_returns_one():
    result = join_incidents(brute=[_SAMPLE_INCIDENT], port=[], flood=[])
    assert result["counts"]["incidents"] == 1


def test_join_incidents_multiple_detectors_sums_counts():
    result = join_incidents(
        brute=[_SAMPLE_INCIDENT],
        port=[{**_SAMPLE_INCIDENT, "incident_type": "port_scan"}],
        flood=[],
    )
    assert result["counts"]["incidents"] == 2


# ---------------------------------------------------------------------------
# _switch_incident_route: mirrors the Conductor JS expression
# ---------------------------------------------------------------------------

def test_switch_route_zero_returns_no_incidents():
    assert _switch_incident_route(0) == "no_incidents"


def test_switch_route_one_returns_has_incidents():
    assert _switch_incident_route(1) == "has_incidents"


def test_switch_route_large_count_returns_has_incidents():
    assert _switch_incident_route(999) == "has_incidents"


def test_switch_route_only_returns_known_cases():
    for n in range(20):
        assert _switch_incident_route(n) in ("no_incidents", "has_incidents")


# ---------------------------------------------------------------------------
# Routing behavior: enrich_geoip not invoked on zero-incident path
# ---------------------------------------------------------------------------

def test_enrich_geoip_not_called_on_zero_incidents():
    """SWITCH routes to TERMINATE before enrich_geoip when incident count is 0."""
    called = []

    def fake_enrich(**kw):
        called.append(kw)
        return {"incidents": kw["incidents"]}

    result = _simulate_orchestrated_pipeline([], {}, enrich_fn=fake_enrich)

    assert called == [], "enrich_geoip must not be invoked on the zero-incident path"
    assert result["status"] == "COMPLETED"
    assert result["reason"] == "no_threats_detected"


def test_enrich_geoip_called_on_nonzero_incidents():
    """SWITCH routes past TERMINATE to enrich_geoip when incidents are present."""
    called = []

    def fake_enrich(**kw):
        called.append(kw)
        return {"incidents": kw["incidents"]}

    _simulate_orchestrated_pipeline([_SAMPLE_INCIDENT], {}, enrich_fn=fake_enrich)
    assert len(called) == 1


def test_summary_not_called_on_zero_incidents():
    summary_calls = []

    def fake_summary(**kw):
        summary_calls.append(kw)

    _simulate_orchestrated_pipeline([], {}, summary_fn=fake_summary)
    assert summary_calls == []


def test_push_not_called_on_zero_incidents():
    push_calls = []

    def fake_push(**kw):
        push_calls.append(kw)
        return {"pushed": 0}

    _simulate_orchestrated_pipeline([], {}, push_fn=fake_push)
    assert push_calls == []


def test_zero_incident_result_shows_zero_pushed():
    result = _simulate_orchestrated_pipeline([], {})
    assert result["pushed"] == 0


def test_nonzero_incident_result_shows_has_incidents_route():
    result = _simulate_orchestrated_pipeline([_SAMPLE_INCIDENT], {})
    assert result["route"] == "has_incidents"


def test_all_downstream_stages_called_on_nonzero_incidents():
    enrich_calls, summary_calls, push_calls = [], [], []

    def fake_enrich(**kw):
        enrich_calls.append(kw)
        return {"incidents": kw["incidents"]}

    def fake_summary(**kw):
        summary_calls.append(kw)

    def fake_push(**kw):
        push_calls.append(kw)
        return {"pushed": len(kw["incidents"])}

    _simulate_orchestrated_pipeline(
        [_SAMPLE_INCIDENT], {},
        enrich_fn=fake_enrich, summary_fn=fake_summary, push_fn=fake_push,
    )
    assert len(enrich_calls) == 1
    assert len(summary_calls) == 1
    assert len(push_calls) == 1


# ---------------------------------------------------------------------------
# Workflow JSON structural validation
# ---------------------------------------------------------------------------

def test_orchestrated_workflow_json_exists():
    assert (_REPO / "conductor_orchestrated.json").exists()


def test_orchestrated_workflow_json_correct_name():
    spec = json.loads((_REPO / "conductor_orchestrated.json").read_text())
    assert spec["name"] == "log_analyzer_soc_pipeline_orchestrated"


def test_orchestrated_workflow_json_has_switch_task():
    spec = json.loads((_REPO / "conductor_orchestrated.json").read_text())
    types = {t["type"] for t in spec["tasks"]}
    assert "SWITCH" in types, "Workflow must contain a SWITCH task"


def test_orchestrated_workflow_json_switch_uses_javascript_evaluator():
    spec = json.loads((_REPO / "conductor_orchestrated.json").read_text())
    switch_task = next(t for t in spec["tasks"] if t["type"] == "SWITCH")
    assert switch_task.get("evaluatorType") == "javascript"
    assert "expression" in switch_task


def test_orchestrated_workflow_json_has_terminate_in_no_incidents_case():
    spec = json.loads((_REPO / "conductor_orchestrated.json").read_text())
    switch_task = next(t for t in spec["tasks"] if t["type"] == "SWITCH")
    no_incidents = switch_task.get("decisionCases", {}).get("no_incidents", [])
    assert any(t["type"] == "TERMINATE" for t in no_incidents), (
        "no_incidents case must contain a TERMINATE task"
    )


def test_orchestrated_workflow_json_terminate_status_is_completed():
    spec = json.loads((_REPO / "conductor_orchestrated.json").read_text())
    switch_task = next(t for t in spec["tasks"] if t["type"] == "SWITCH")
    terminate_task = next(
        t for t in switch_task["decisionCases"]["no_incidents"]
        if t["type"] == "TERMINATE"
    )
    assert terminate_task["inputParameters"]["terminationStatus"] == "COMPLETED"


def test_orchestrated_workflow_json_terminate_reason_is_no_threats_detected():
    spec = json.loads((_REPO / "conductor_orchestrated.json").read_text())
    switch_task = next(t for t in spec["tasks"] if t["type"] == "SWITCH")
    terminate_task = next(
        t for t in switch_task["decisionCases"]["no_incidents"]
        if t["type"] == "TERMINATE"
    )
    assert terminate_task["inputParameters"]["terminationReason"] == "no_threats_detected"


def test_orchestrated_workflow_json_enrich_is_top_level_task():
    """enrich_geoip must be a top-level task (not nested inside a SWITCH case).

    Being top-level means Conductor only reaches it after the SWITCH completes
    without terminating — i.e., only when incident_count > 0.
    """
    spec = json.loads((_REPO / "conductor_orchestrated.json").read_text())
    top_level_names = {t.get("name") for t in spec["tasks"]}
    assert "enrich_geoip" in top_level_names, (
        "enrich_geoip must be a top-level workflow task, not nested inside SWITCH cases"
    )


def test_orchestrated_workflow_json_has_required_input_parameters():
    spec = json.loads((_REPO / "conductor_orchestrated.json").read_text())
    assert "log_path" in spec["inputParameters"]
    assert "soc_url" in spec["inputParameters"]
    assert "soc_api_key" in spec["inputParameters"]
