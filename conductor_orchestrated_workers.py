"""Worker helpers and new task implementations for log_analyzer_soc_pipeline_orchestrated.

Phase 1 — this module adds testability helpers for the SWITCH+TERMINATE routing
logic. No new @worker_task functions are needed in Phase 1: SWITCH and TERMINATE
are built-in Conductor system task types with no Python worker counterpart.

Phase 2 will add @worker_task functions for run_ai_agent, generate_sigma_rules,
elasticsearch_ingest, and gcs_upload_report.

SDK annotation rules (same as conductor_workers.py):
  * No ``from __future__ import annotations`` — the SDK reads real annotations.
  * List parameters typed as ``List[dict]``, not ``list[dict]`` or bare ``list``.
  * Never pass datetime objects or large event lists across task boundaries.
"""
import os
import sys
from typing import Callable, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


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
