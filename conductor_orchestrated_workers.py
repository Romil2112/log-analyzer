"""Worker helpers and new task implementations for log_analyzer_soc_pipeline_orchestrated.

Phase 1 — SWITCH routing helper and pipeline simulation for testing.
Phase 2 — four @worker_task functions that run in the second (post-enrichment) FORK_JOIN:
  run_ai_agent        wraps ai_agent.run_investigation
  generate_sigma_rules wraps sigma_export.export_sigma_llm
  elasticsearch_ingest wraps es_ingest.connect/ensure_index/index_incidents
  gcs_upload_report   wraps log_analyzer._upload_to_gcs

SDK annotation rules (same as conductor_workers.py):
  * No ``from __future__ import annotations`` — the SDK reads real annotations.
  * List parameters typed as ``List[dict]``, not ``list[dict]`` or bare ``list``.
  * Never pass datetime objects or large event lists across task boundaries.
  * Keep heavy I/O inside one worker; only small JSON-safe payloads cross task boundaries.
"""
import os
import sys
from typing import Callable, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from conductor.client.worker.worker_task import worker_task

from ai_agent import run_investigation
from es_ingest import connect as es_connect
from es_ingest import ensure_index as es_ensure_index
from es_ingest import index_incidents as es_index_incidents
from log_analyzer import _upload_to_gcs
from sigma_export import export_sigma_llm


# ---------------------------------------------------------------------------
# Phase 1 — SWITCH routing helper
# ---------------------------------------------------------------------------

def _switch_incident_route(incident_count: int) -> str:
    """Return the Conductor SWITCH case key for a given incident count.

    Mirrors the JavaScript expression in conductor_orchestrated.json:
        $.incident_count === 0 ? 'no_incidents' : 'has_incidents'

    Exists as a standalone Python function so the routing logic can be unit-tested
    without a live Conductor server.
    """
    return "no_incidents" if incident_count == 0 else "has_incidents"


def _simulate_orchestrated_pipeline(
    incidents: List[dict],
    anomaly_scores: dict,
    *,
    enrich_fn: Optional[Callable] = None,
    summary_fn: Optional[Callable] = None,
    push_fn: Optional[Callable] = None,
) -> dict:
    """Python-level simulation of log_analyzer_soc_pipeline_orchestrated.

    Embeds the same SWITCH routing logic as the Conductor workflow JSON, making
    the per-branch behavior testable without a live Conductor server. Pass stub
    callables via enrich_fn / summary_fn / push_fn to observe which stages are
    (or are not) invoked under each routing branch.

    On the 'no_incidents' branch the function returns immediately without calling
    any of the downstream stubs — matching what the TERMINATE task does in the
    real workflow.
    """
    route = _switch_incident_route(len(incidents))

    if route == "no_incidents":
        return {"status": "COMPLETED", "reason": "no_threats_detected", "pushed": 0}

    enriched_incidents = incidents
    if enrich_fn is not None:
        result = enrich_fn(incidents=incidents, anomaly_scores=anomaly_scores)
        enriched_incidents = result.get("incidents", incidents)

    if summary_fn is not None:
        summary_fn(incidents=enriched_incidents, anomaly_scores=anomaly_scores)

    pushed = 0
    if push_fn is not None:
        result = push_fn(incidents=enriched_incidents)
        pushed = result.get("pushed", len(enriched_incidents))

    return {"status": "COMPLETED", "route": "has_incidents", "pushed": pushed}


# ---------------------------------------------------------------------------
# Phase 2 — post-enrichment FORK_JOIN workers
# ---------------------------------------------------------------------------

@worker_task(task_definition_name="run_ai_agent")
def run_ai_agent(incidents: List[dict], anomaly_scores: dict = None) -> dict:
    """Post-enrichment FORK branch: multi-step Claude tool-use investigation.

    Wraps ai_agent.run_investigation(). Each tool-use round has a 60 s timeout
    (set in ai_agent.py) and at most MAX_ROUNDS=5 rounds, so worst-case API time
    is ~360 s. The task-def response_timeout is set to 420 s to give margin.
    Returns report=None (not an error) when ANTHROPIC_API_KEY is unset so this
    branch never fails the workflow for a missing key.
    """
    if not incidents:
        return {"report": None, "note": "no incidents to investigate"}
    try:
        report = run_investigation(incidents, conn=None)
    except Exception as exc:
        return {"report": None, "note": f"investigation skipped: {type(exc).__name__}"}
    return {"report": report, "note": None if report else "ANTHROPIC_API_KEY unset or no content"}


@worker_task(task_definition_name="generate_sigma_rules")
def generate_sigma_rules(incidents: List[dict], out_dir: str = "/tmp/conductor_sigma") -> dict:
    """Post-enrichment FORK branch: LLM-powered Sigma rule generation.

    Wraps sigma_export.export_sigma_llm(). Writes one <type>_llm.yml per distinct
    incident type. Returns an empty file list (not an error) when ANTHROPIC_API_KEY
    is unset or the API call fails, so the branch never blocks the downstream JOIN.
    """
    if not incidents:
        return {"files": [], "count": 0, "note": "no incidents"}
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return {"files": [], "count": 0, "note": "ANTHROPIC_API_KEY unset"}
    try:
        from anthropic import Anthropic
        client = Anthropic(api_key=key)
        files = export_sigma_llm(incidents, out_dir, client)
    except Exception as exc:
        return {"files": [], "count": 0, "note": f"sigma generation failed: {type(exc).__name__}"}
    return {"files": files, "count": len(files), "note": None}


@worker_task(task_definition_name="elasticsearch_ingest")
def elasticsearch_ingest(incidents: List[dict], es_host: str = "", log_path: str = "") -> dict:
    """Post-enrichment FORK branch: bulk-index incidents into Elasticsearch.

    Wraps es_ingest.connect/ensure_index/index_incidents. Returns indexed=0 when
    es_host is unset or the cluster is unreachable — same graceful degradation as
    the existing --es-host CLI flag.
    """
    if not incidents or not es_host:
        note = "es_host not configured" if incidents else "no incidents"
        return {"indexed": 0, "note": note}
    client = es_connect(es_host)
    if client is None:
        return {"indexed": 0, "note": f"could not connect to ES at {es_host}"}
    es_ensure_index(client)
    count = es_index_incidents(client, incidents, log_file=log_path)
    return {"indexed": count, "note": None}


@worker_task(task_definition_name="gcs_upload_report")
def gcs_upload_report(incidents: List[dict], gcs_bucket: str = "", log_path: str = "") -> dict:
    """Post-enrichment FORK branch: upload a JSON incident summary to GCS.

    Wraps log_analyzer._upload_to_gcs(). Creates a temporary JSON file from the
    incident list, uploads it, then cleans up. Returns uploaded=False (not an
    error) when gcs_bucket is unset — matches --gcs-bucket graceful-skip behaviour.
    """
    import argparse
    import json
    import pathlib
    import tempfile

    if not gcs_bucket:
        return {"uploaded": False, "note": "gcs_bucket not configured"}

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", prefix="conductor_report_", delete=False
        ) as fh:
            json.dump(
                {"log_path": log_path, "incident_count": len(incidents), "incidents": incidents},
                fh,
            )
            tmp_path = fh.name

        args = argparse.Namespace(gcs_bucket=gcs_bucket, report=tmp_path)
        _upload_to_gcs(tmp_path, args)
        return {"uploaded": True, "blob": pathlib.Path(tmp_path).name, "note": None}
    except Exception as exc:
        return {"uploaded": False, "note": f"upload failed: {type(exc).__name__}: {exc}"}
    finally:
        if tmp_path:
            try:
                pathlib.Path(tmp_path).unlink(missing_ok=True)
            except Exception:
                pass
