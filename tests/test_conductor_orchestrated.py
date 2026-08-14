"""Tests for log_analyzer_soc_pipeline_orchestrated — Phase 1 & 2.

Phase 1 covers:
  - join_incidents returns zero incident count for empty detector output
  - _switch_incident_route mirrors the Conductor JS expression correctly
  - enrich_geoip (and downstream stages) are never invoked on the zero-incident path
  - The workflow JSON has the required structural properties (SWITCH present,
    TERMINATE in the no_incidents case, enrich_geoip as a top-level task)

Phase 2 covers:
  - run_ai_agent: calls run_investigation with a mocked Anthropic client
  - generate_sigma_rules: calls export_sigma_llm with a mocked Anthropic client
  - elasticsearch_ingest: calls real es_ingest functions with a mocked ES client
  - gcs_upload_report: calls real _upload_to_gcs with a mocked GCS module
  - Workflow JSON structure: second FORK_JOIN, 5-branch output fork, updated params
"""
import json
import os
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from conductor_orchestrated_workers import (
    _simulate_orchestrated_pipeline,
    _switch_incident_route,
    elasticsearch_ingest,
    gcs_upload_report,
    generate_sigma_rules,
    run_ai_agent,
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


# ---------------------------------------------------------------------------
# Phase 2 — new worker: graceful-degradation paths (no external deps needed)
# ---------------------------------------------------------------------------

def test_run_ai_agent_empty_incidents_skips_investigation():
    result = run_ai_agent(incidents=[])
    assert result["report"] is None
    assert "no incidents" in result["note"]


def test_generate_sigma_rules_empty_incidents():
    result = generate_sigma_rules(incidents=[])
    assert result["files"] == []
    assert result["count"] == 0
    assert result["note"] == "no incidents"


def test_generate_sigma_rules_no_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = generate_sigma_rules(incidents=[_SAMPLE_INCIDENT])
    assert result["files"] == []
    assert result["count"] == 0
    assert "unset" in result["note"]


def test_elasticsearch_ingest_empty_incidents():
    result = elasticsearch_ingest(incidents=[], es_host="http://localhost:9200")
    assert result["indexed"] == 0
    assert "no incidents" in result["note"]


def test_elasticsearch_ingest_no_host():
    result = elasticsearch_ingest(incidents=[_SAMPLE_INCIDENT], es_host="")
    assert result["indexed"] == 0
    assert "not configured" in result["note"]


def test_gcs_upload_report_no_bucket():
    result = gcs_upload_report(incidents=[_SAMPLE_INCIDENT], gcs_bucket="")
    assert result["uploaded"] is False
    assert "not configured" in result["note"]


# ---------------------------------------------------------------------------
# Phase 2 — run_ai_agent: invokes real run_investigation with mocked Anthropic
# ---------------------------------------------------------------------------

class _FakeTextBlock:
    type = "text"
    text = "Threat investigation complete. Recommend blocking 10.0.0.1."


class _FakeResponse:
    stop_reason = "end_turn"
    content = [_FakeTextBlock()]


class _FakeMessages:
    def create(self, **kwargs):
        return _FakeResponse()


class _FakeAnthropicClient:
    def __init__(self, api_key=None):
        self.messages = _FakeMessages()


def test_run_ai_agent_calls_real_run_investigation(monkeypatch):
    """run_ai_agent must call run_investigation (not a stub); Anthropic is mocked."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")
    monkeypatch.setattr("anthropic.Anthropic", _FakeAnthropicClient)

    result = run_ai_agent(incidents=[_SAMPLE_INCIDENT])

    assert result["note"] is None, f"Expected no note (success path), got: {result['note']}"
    assert isinstance(result["report"], str)
    assert len(result["report"]) > 0


def test_run_ai_agent_returns_none_report_when_api_key_unset(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = run_ai_agent(incidents=[_SAMPLE_INCIDENT])
    assert result["report"] is None


# ---------------------------------------------------------------------------
# Phase 2 — generate_sigma_rules: invokes real export_sigma_llm with mocked Anthropic
# ---------------------------------------------------------------------------

_SIGMA_YAML = """\
title: Brute Force Authentication Detection
id: 00000000-0000-4000-a000-000000000001
status: experimental
description: Detects repeated failed login attempts.
author: log-analyzer
date: 2024/01/01
tags:
  - attack.credential_access
logsource:
  category: authentication
detection:
  selection:
    EventID: 4625
  condition: selection | count() by SourceAddress > 10
falsepositives:
  - Legitimate admin activity
level: high
"""


class _SigmaMessages:
    def create(self, **kwargs):
        class _R:
            content = [type("B", (), {"text": _SIGMA_YAML})()]
        return _R()


class _SigmaAnthropicClient:
    def __init__(self, api_key=None):
        self.messages = _SigmaMessages()


def test_generate_sigma_rules_calls_real_export_sigma_llm(monkeypatch, tmp_path):
    """generate_sigma_rules must call export_sigma_llm (not a stub); Anthropic is mocked."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")
    monkeypatch.setattr("anthropic.Anthropic", _SigmaAnthropicClient)

    result = generate_sigma_rules(
        incidents=[_SAMPLE_INCIDENT],
        out_dir=str(tmp_path),
    )

    assert result["count"] >= 1, f"Expected at least one Sigma file, got: {result}"
    assert len(result["files"]) == result["count"]
    assert result["note"] is None
    # Confirm the real export_sigma_llm wrote a file on disk.
    written = list(tmp_path.iterdir())
    assert written, "export_sigma_llm must write at least one .yml file"


# ---------------------------------------------------------------------------
# Phase 2 — elasticsearch_ingest: real es_ingest functions with mocked ES client
# ---------------------------------------------------------------------------

def test_elasticsearch_ingest_calls_real_es_functions(monkeypatch):
    """elasticsearch_ingest must call the real es_ingest chain; Elasticsearch is mocked."""
    mock_client = MagicMock()
    # ensure_index checks client.indices.exists; return False to trigger creation path
    mock_client.indices.exists.return_value = False
    mock_client.indices.create.return_value = {}
    # index_incidents calls elasticsearch.helpers.bulk; patch it to succeed
    mock_bulk = MagicMock(return_value=(1, []))

    import conductor_orchestrated_workers as cow
    # Patch es_connect to return our mock client (skips network ping).
    monkeypatch.setattr(cow, "es_connect", lambda host: mock_client)
    # Patch bulk inside es_ingest so index_incidents runs its real body.
    with patch("elasticsearch.helpers.bulk", mock_bulk):
        result = elasticsearch_ingest(
            incidents=[_SAMPLE_INCIDENT],
            es_host="http://localhost:9200",
            log_path="/tmp/test.log",
        )

    assert result["indexed"] == 1, f"Expected 1 indexed, got: {result}"
    assert result["note"] is None
    # Confirm ensure_index ran (real function checked indices.exists).
    mock_client.indices.exists.assert_called_once()


def test_elasticsearch_ingest_connect_returns_none_when_unreachable(monkeypatch):
    """When es_connect returns None the worker degrades gracefully."""
    import conductor_orchestrated_workers as cow
    monkeypatch.setattr(cow, "es_connect", lambda host: None)
    result = elasticsearch_ingest(incidents=[_SAMPLE_INCIDENT], es_host="http://bad-host:9200")
    assert result["indexed"] == 0
    assert "could not connect" in result["note"]


# ---------------------------------------------------------------------------
# Phase 2 — gcs_upload_report: real _upload_to_gcs with mocked google.cloud.storage
# ---------------------------------------------------------------------------

def _make_mock_gcs_module():
    """Return a mock google.cloud.storage module whose Client chain does nothing."""
    mock_blob = MagicMock()
    mock_blob.upload_from_filename.return_value = None
    mock_bucket = MagicMock()
    mock_bucket.blob.return_value = mock_blob
    mock_gcs_client = MagicMock()
    mock_gcs_client.bucket.return_value = mock_bucket
    mock_gcs_cls = MagicMock(return_value=mock_gcs_client)

    mod = types.ModuleType("google.cloud.storage")
    mod.Client = mock_gcs_cls
    return mod, mock_blob


def test_gcs_upload_report_calls_real_upload_to_gcs(monkeypatch):
    """gcs_upload_report must call _upload_to_gcs (not a stub); GCS is mocked."""
    mock_gcs_mod, mock_blob = _make_mock_gcs_module()

    # Inject the mock module so the lazy `from google.cloud import storage` inside
    # _upload_to_gcs gets our stub instead of the real SDK.
    monkeypatch.setitem(sys.modules, "google.cloud.storage", mock_gcs_mod)
    # Ensure the top-level packages exist in sys.modules so the import chain resolves.
    if "google" not in sys.modules:
        monkeypatch.setitem(sys.modules, "google", types.ModuleType("google"))
    if "google.cloud" not in sys.modules:
        monkeypatch.setitem(sys.modules, "google.cloud", types.ModuleType("google.cloud"))

    result = gcs_upload_report(
        incidents=[_SAMPLE_INCIDENT],
        gcs_bucket="test-bucket",
        log_path="/tmp/test.log",
    )

    assert result["uploaded"] is True, f"Expected uploaded=True, got: {result}"
    assert result["note"] is None
    # Confirm the real _upload_to_gcs called through to GCS blob upload.
    mock_blob.upload_from_filename.assert_called_once()


def test_gcs_upload_report_handles_serialization_error():
    """gcs_upload_report must degrade gracefully when incident JSON-serialization fails.

    _upload_to_gcs swallows internal GCS errors by design. The worker's own
    except block fires only for failures that happen before _upload_to_gcs is
    called — like a non-JSON-serializable object in the incidents list.
    """
    class _Unserializable:
        pass

    result = gcs_upload_report(
        incidents=[{"obj": _Unserializable()}],
        gcs_bucket="test-bucket",
        log_path="/tmp/test.log",
    )

    assert result["uploaded"] is False
    assert "upload failed" in result["note"]


# ---------------------------------------------------------------------------
# Phase 2 — Workflow JSON structural validation: second FORK_JOIN
# ---------------------------------------------------------------------------

def _get_top_level_task(spec: dict, task_type: str, nth: int = 0):
    """Return the nth top-level task matching task_type (0-indexed)."""
    matches = [t for t in spec["tasks"] if t["type"] == task_type]
    assert len(matches) > nth, f"Expected >{nth} tasks of type {task_type}, found {len(matches)}"
    return matches[nth]


def test_orchestrated_workflow_json_has_two_fork_join_tasks():
    spec = json.loads((_REPO / "conductor_orchestrated.json").read_text())
    fork_tasks = [t for t in spec["tasks"] if t["type"] == "FORK_JOIN"]
    assert len(fork_tasks) == 2, f"Expected 2 FORK_JOIN tasks, found {len(fork_tasks)}"


def test_orchestrated_workflow_json_output_fork_has_five_branches():
    spec = json.loads((_REPO / "conductor_orchestrated.json").read_text())
    output_fork = _get_top_level_task(spec, "FORK_JOIN", nth=1)
    assert len(output_fork["forkTasks"]) == 5, (
        f"Output FORK_JOIN must have 5 branches, found {len(output_fork['forkTasks'])}"
    )


def test_orchestrated_workflow_json_output_fork_branch_names():
    spec = json.loads((_REPO / "conductor_orchestrated.json").read_text())
    output_fork = _get_top_level_task(spec, "FORK_JOIN", nth=1)
    branch_task_names = {branch[0]["name"] for branch in output_fork["forkTasks"]}
    expected = {"generate_claude_summary", "run_ai_agent", "generate_sigma_rules",
                "elasticsearch_ingest", "gcs_upload_report"}
    assert branch_task_names == expected, (
        f"Output fork branches mismatch.\n  Expected: {expected}\n  Got: {branch_task_names}"
    )


def test_orchestrated_workflow_json_output_join_waits_for_all_five():
    spec = json.loads((_REPO / "conductor_orchestrated.json").read_text())
    output_join = _get_top_level_task(spec, "JOIN", nth=1)
    join_on = set(output_join.get("joinOn", []))
    assert len(join_on) == 5, f"Output JOIN must wait on 5 refs, found {len(join_on)}"


def test_orchestrated_workflow_json_push_to_dashboard_is_after_output_join():
    spec = json.loads((_REPO / "conductor_orchestrated.json").read_text())
    task_names = [t.get("name", t.get("taskReferenceName")) for t in spec["tasks"]]
    join_pos = next(
        i for i, t in enumerate(spec["tasks"])
        if t["type"] == "JOIN" and len(t.get("joinOn", [])) == 5
    )
    push_pos = next(i for i, t in enumerate(spec["tasks"]) if t.get("name") == "push_to_dashboard")
    assert push_pos > join_pos, "push_to_dashboard must come after the output JOIN"


def test_orchestrated_workflow_json_has_es_host_and_gcs_bucket_input_params():
    spec = json.loads((_REPO / "conductor_orchestrated.json").read_text())
    assert "es_host" in spec["inputParameters"]
    assert "gcs_bucket" in spec["inputParameters"]


def test_orchestrated_workflow_json_output_params_include_new_workers():
    spec = json.loads((_REPO / "conductor_orchestrated.json").read_text())
    out = spec.get("outputParameters", {})
    assert "agent_report" in out
    assert "sigma_files" in out
    assert "es_indexed" in out
    assert "gcs_uploaded" in out
