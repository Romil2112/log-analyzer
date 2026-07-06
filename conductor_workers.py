"""Orkes Conductor worker adapters for the log-analyzer -> SOC-Dashboard pipeline.

Each ``@worker_task`` below is a thin wrapper around functions that already exist
in this repo -- NO detection/enrichment logic is changed here. The workers poll an
Orkes Conductor server for tasks, run a stage, and hand a small JSON-safe payload to
the next stage.

Design notes (why this differs from the "one worker per stage" sketch):
  * Conductor serializes every task input/output to JSON. Parsed *events* carry
    ``datetime`` objects and can number in the hundreds of thousands, so they are NOT
    passed between tasks. All the heavy in-memory work (parse -> detect -> enrich ->
    ML score) happens inside ``analyze_log`` and only the small list of *incidents*
    (a few hundred dicts) crosses task boundaries.
  * Incident ``datetime`` fields are converted to ISO-8601 strings so the output is
    JSON-safe. The two downstream consumers (ai_summary / soc_push.incident_to_alert)
    only read JSON-safe fields, so this is lossless for them.

Run the workers with ``python3 start_workers.py`` (see that file). This module just
needs to be imported for the ``@worker_task`` decorators to register.

SDK ANNOTATION RULES (learned the hard way):
  * Do NOT add ``from __future__ import annotations`` -- the SDK reads each worker's
    real parameter annotations to deserialize task inputs; PEP 563 stringifies them and
    breaks ``isinstance(value, annotation)``.
  * A *list* parameter MUST be typed ``List[dict]`` (parameterized): the SDK does
    ``typing.get_args(annotation)[0]`` to find the element type, so bare ``list`` throws
    IndexError. Scalars/dicts are fine bare (str/bool/dict). Avoid ``dict | None`` (the
    SDK's isinstance check rejects PEP-604 unions) -- use ``dict`` with a ``None`` default.
"""
import datetime as _dt
import os
import sys
from typing import List

# Make the sibling log-analyzer modules importable no matter the working directory.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from conductor.client.worker.worker_task import worker_task

import log_analyzer as la
import enrichment
from ai_summary import ai_summary
from soc_push import push_incidents

_PARSERS = {
    "ssh": la.parse_ssh_log,
    "web": la.parse_web_log,
    "windows": la.parse_windows_csv,
}


def _json_safe(obj):
    """Recursively convert datetimes to ISO strings so Conductor can serialize the
    task output. Leaves everything else untouched."""
    if isinstance(obj, _dt.datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    return obj


@worker_task(task_definition_name="analyze_log")
def analyze_log(
    log_path: str,
    log_format: str = "auto",
    enrich_ip: bool = True,
    run_ml: bool = True,
) -> dict:
    """Stage 1: parse -> detect (brute-force/port-scan/404-flood) -> enrich -> ML score.

    Returns a JSON-safe payload; ``events`` stay in this process, only ``incidents``
    (with severity + MITRE + optional GeoIP/threat-intel + anomaly scores) flow on.
    """
    fmt = la.detect_log_format(log_path) if log_format == "auto" else log_format
    parser = _PARSERS.get(fmt)
    if parser is None:
        raise ValueError(f"unsupported log_format {fmt!r} (expected ssh/web/windows/auto)")

    events = parser(log_path)

    # Rule detection + severity/MITRE (same public path main() uses).
    incidents: list[dict] = []
    incidents += la.detect_brute_force(events)
    incidents += la.detect_port_scan(events)
    incidents += la.detect_404_flood(events)
    incidents = la.enrich_incidents(incidents)  # adds severity + mitre

    # Optional IP enrichment (bundled threat-intel + GeoIP, both degrade gracefully).
    if enrich_ip:
        networks = enrichment.load_threat_intel()
        geo = enrichment.GeoIP()
        try:
            incidents = enrichment.enrich_incidents(incidents, networks, geo)
        finally:
            geo.close()

    # Optional IsolationForest anomaly scores (returns {} if sklearn/data insufficient).
    anomaly_scores: dict[str, float] = {}
    if run_ml:
        anomaly_scores = la.AnomalyDetector().fit_score(events)

    counts: dict[str, int] = {"events": len(events), "incidents": len(incidents)}
    for inc in incidents:
        counts[inc["incident_type"]] = counts.get(inc["incident_type"], 0) + 1

    return _json_safe(
        {
            "incidents": incidents,
            "anomaly_scores": anomaly_scores,
            "counts": counts,
            "log_format": fmt,
        }
    )


@worker_task(task_definition_name="generate_claude_summary")
def generate_claude_summary(incidents: List[dict], anomaly_scores: dict = None) -> dict:
    """Stage 2: a 3-sentence SOC executive summary via the Claude API.

    Returns ``summary=None`` (no error) when ANTHROPIC_API_KEY is unset, so the
    workflow can proceed to push even without an API key configured on the worker.
    """
    if not incidents:
        return {"summary": None, "note": "no incidents to summarize"}
    summary = ai_summary(incidents, anomaly_scores or {})
    return {
        "summary": summary,
        "note": None if summary else "ANTHROPIC_API_KEY unset or empty response",
    }


@worker_task(task_definition_name="push_to_dashboard")
def push_to_dashboard(incidents: List[dict], soc_url: str, soc_api_key: str = "") -> dict:
    """Stage 3: POST each incident to SOC-Dashboard's ``/api/alerts`` ingest endpoint.

    ``soc_url`` example: ``http://localhost:8000/api/alerts``. ``soc_api_key`` must
    match SOC-Dashboard's ``ALERTS_API_KEY`` or every POST 401s.
    """
    if not incidents:
        return {"pushed": 0, "errors": [], "total": 0}
    ok, errors = push_incidents(incidents, soc_url, api_key=soc_api_key or None)
    return {"pushed": ok, "errors": errors, "total": len(incidents)}
