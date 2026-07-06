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


def _parse(log_path, log_format):
    """Resolve the format and parse the log into events. Kept as a helper because each
    forked detector task re-parses the log locally (raw events, which carry datetimes and
    can number in the hundreds of thousands, must never cross a Conductor task boundary)."""
    fmt = la.detect_log_format(log_path) if log_format == "auto" else log_format
    parser = _PARSERS.get(fmt)
    if parser is None:
        raise ValueError(f"unsupported log_format {fmt!r} (expected ssh/web/windows/auto)")
    return parser(log_path), fmt


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


# ── Fork/join variant (workflow v2) ───────────────────────────────────────────
# v2 splits analyze_log into four parallel tasks (the three detectors + ML scoring)
# that fan out from a FORK_JOIN, then a JOIN feeds join_incidents, which merges and
# enriches. Each parallel task takes only the log_path (a string) and re-parses the
# log locally, so raw events never cross a task boundary -- only small incident lists
# and the anomaly-score dict do. The tradeoff is the log is parsed once per branch.


@worker_task(task_definition_name="detect_brute_force")
def detect_brute_force(log_path: str, log_format: str = "auto") -> dict:
    """Fork branch: parse the log locally and run only the brute-force detector."""
    events, fmt = _parse(log_path, log_format)
    incidents = la.detect_brute_force(events)
    return _json_safe({"incidents": incidents, "log_format": fmt, "count": len(incidents)})


@worker_task(task_definition_name="detect_port_scan")
def detect_port_scan(log_path: str, log_format: str = "auto") -> dict:
    """Fork branch: parse the log locally and run only the port-scan detector."""
    events, fmt = _parse(log_path, log_format)
    incidents = la.detect_port_scan(events)
    return _json_safe({"incidents": incidents, "log_format": fmt, "count": len(incidents)})


@worker_task(task_definition_name="detect_404_flood")
def detect_404_flood(log_path: str, log_format: str = "auto") -> dict:
    """Fork branch: parse the log locally and run only the 404-flood / web-scan detector
    (returns an empty list for non-web logs, which is expected)."""
    events, fmt = _parse(log_path, log_format)
    incidents = la.detect_404_flood(events)
    return _json_safe({"incidents": incidents, "log_format": fmt, "count": len(incidents)})


@worker_task(task_definition_name="ml_score")
def ml_score(log_path: str, log_format: str = "auto") -> dict:
    """Fork branch: parse the log locally and run the IsolationForest anomaly scorer.
    Returns per-source-IP scores (``{}`` if sklearn/data insufficient) plus the event count
    so the workflow output can still report total events."""
    events, _ = _parse(log_path, log_format)
    scores = la.AnomalyDetector().fit_score(events) if events else {}
    return {"anomaly_scores": scores, "events": len(events)}


@worker_task(task_definition_name="join_incidents")
def join_incidents(
    brute: List[dict],
    port: List[dict],
    flood: List[dict],
    anomaly_scores: dict = None,
    events: int = 0,
) -> dict:
    """Join task: merge the three detectors' incident lists and attach severity + MITRE
    (``la.enrich_incidents`` -- cheap, local, no external calls). Threat-intel + GeoIP
    enrichment is a separate downstream task (``enrich_geoip``) as of workflow v3.
    ``la.enrich_incidents`` keys off incident_type / event_count only -- never the
    ISO-string timestamps -- so running it after the fork boundary is lossless."""
    incidents: list[dict] = list(brute or []) + list(port or []) + list(flood or [])
    incidents = la.enrich_incidents(incidents)  # severity + MITRE

    counts: dict[str, int] = {"events": events, "incidents": len(incidents)}
    for inc in incidents:
        counts[inc["incident_type"]] = counts.get(inc["incident_type"], 0) + 1

    return _json_safe(
        {"incidents": incidents, "anomaly_scores": anomaly_scores or {}, "counts": counts}
    )


@worker_task(task_definition_name="enrich_geoip")
def enrich_geoip(incidents: List[dict], anomaly_scores: dict = None) -> dict:
    """v3/v4 stage: attach threat-intel (``known_bad``) + GeoIP (``country``) to each
    incident, and (v4) fold in the richer per-incident fields so one dict carries
    severity + MITRE + geo + threat-intel + anomaly score together.

    Kept as its own task so the lookups are an independently timed, retryable stage in the
    Orkes view. The threat-intel CIDR list and the MaxMind GeoIP reader are both LOCAL
    (a file read + an .mmdb open -- no network calls); they are built and closed inside
    this worker, so only the small incident list crosses the task boundary. ``country`` is
    ``"Unknown"`` when GEOIP_DB_PATH is unset, which keeps the stage working offline.

    v4 additions per incident: ``anomaly_score`` (merged by source_ip from the ml_score
    output, ``None`` when that IP has no score -- honest, not an error) and a flat
    ``mitre_id`` for at-a-glance display alongside the existing nested ``mitre`` dict. The
    task also returns small aggregate stats so the Orkes output panel shows substance."""
    if not incidents:
        return {"incidents": [], "enriched": 0, "known_bad_count": 0, "countries": {}, "scored": 0}

    networks = enrichment.load_threat_intel()
    geo = enrichment.GeoIP()
    try:
        enriched = enrichment.enrich_incidents(incidents, networks, geo)  # + country, known_bad
    finally:
        geo.close()

    scores = anomaly_scores or {}
    countries: dict[str, int] = {}
    for inc in enriched:
        inc["anomaly_score"] = scores.get(inc.get("source_ip"))  # None if this IP wasn't scored
        inc["mitre_id"] = (inc.get("mitre") or {}).get("id")
        country = inc.get("country", "Unknown")
        countries[country] = countries.get(country, 0) + 1

    return _json_safe(
        {
            "incidents": enriched,
            "enriched": len(enriched),
            "known_bad_count": sum(1 for i in enriched if i.get("known_bad")),
            "countries": countries,
            "scored": sum(1 for i in enriched if i.get("anomaly_score") is not None),
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
    try:
        summary = ai_summary(incidents, anomaly_scores or {})
    except Exception as exc:  # noqa: BLE001 -- summary is optional; never fail the pipeline for it
        # An unset key already returns None inside ai_summary. An *invalid* key or a
        # transient API/network error should degrade the same way rather than failing
        # the whole workflow and blocking the downstream SOC push.
        return {"summary": None, "note": f"summary skipped: {type(exc).__name__}"}
    return {
        "summary": summary,
        "note": None if summary else "ANTHROPIC_API_KEY unset or empty response",
    }


def _collect_task_timings(workflow_id: str) -> dict:
    """Best-effort: read this workflow's completed task durations from Conductor.

    push_to_dashboard is the last task, so every upstream task is already COMPLETED by
    the time this runs. Any failure (network, auth, SDK) degrades to ``None`` -- provenance
    is a nice-to-have and must never block the SOC push (same discipline as the summary
    stage). The Conductor client is imported lazily so this coupling only loads when used."""
    try:
        from conductor.client.configuration.configuration import Configuration
        from conductor.client.orkes.orkes_workflow_client import OrkesWorkflowClient

        w = OrkesWorkflowClient(Configuration()).get_workflow(workflow_id, include_tasks=True)
        seconds = {
            t.reference_task_name: round((t.end_time - t.start_time) / 1000.0, 3)
            for t in w.tasks
            if t.start_time and t.end_time
        }
        return {"workflow_id": workflow_id, "task_seconds": seconds}
    except Exception:  # noqa: BLE001 -- provenance is optional; never fail the push for it
        return None


@worker_task(task_definition_name="push_to_dashboard")
def push_to_dashboard(
    incidents: List[dict], soc_url: str, soc_api_key: str = "", workflow_id: str = ""
) -> dict:
    """Stage 3: POST each incident to SOC-Dashboard's ``/api/alerts`` ingest endpoint.

    ``soc_url`` example: ``http://localhost:8000/api/alerts``. ``soc_api_key`` must
    match SOC-Dashboard's ``ALERTS_API_KEY`` or every POST 401s. ``workflow_id`` (wired
    from ``${workflow.workflowId}``) is stored on each alert as provenance, along with a
    best-effort per-task timing blob, so the dashboard can trace an alert to its run.
    """
    if not incidents:
        return {"pushed": 0, "errors": [], "total": 0}
    run_metadata = _collect_task_timings(workflow_id) if workflow_id else None
    ok, errors = push_incidents(
        incidents, soc_url, api_key=soc_api_key or None,
        workflow_run_id=workflow_id or None, run_metadata=run_metadata,
    )
    return {"pushed": ok, "errors": errors, "total": len(incidents), "workflow_run_id": workflow_id or None}
