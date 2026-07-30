"""
gRPC client for the SOC Dashboard Go ingest microservice.

This module is an opt-in companion to soc_push.py. It sends detected incidents
over gRPC (port 9001) to the Go ingest-service rather than over HTTP to Flask.
grpcio is an optional dependency: import failures are caught and surfaced as
errors so the rest of log-analyzer continues to work without it.
"""
from __future__ import annotations

import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

from tracing import inject_grpc_metadata

__all__ = ["push_incidents_grpc"]

# log-analyzer incident_type -> SOC-Dashboard alert category (mirrors soc_push.py)
_CATEGORY = {
    "brute_force": "brute_force",
    "port_scan":   "port_scan",
    "flood_404":   "anomaly",
}

_TITLE = {
    "brute_force": "Brute-force attack from {ip}",
    "port_scan":   "Port scan from {ip}",
    "flood_404":   "Web 404 flood / scanning from {ip}",
}


def _incident_to_request(incident: dict, workflow_run_id: str | None, run_metadata: str | None):
    """Build an IngestAlertRequest from a log-analyzer incident dict."""
    from proto.ingest_pb2 import IngestAlertRequest  # type: ignore[import]

    itype = incident.get("incident_type", "incident")
    ip    = incident.get("source_ip") or "unknown"
    mitre = incident.get("mitre", {}) or {}
    title = _TITLE.get(itype, f"{itype.replace('_', ' ').title()} from {{ip}}").format(ip=ip)
    desc  = (
        f"{incident.get('event_count', 0)} events; "
        f"MITRE {mitre.get('id', '-')} ({mitre.get('tactic', '-')})."
    )
    return IngestAlertRequest(
        title=title,
        category=_CATEGORY.get(itype, "anomaly"),
        severity=incident.get("severity", "LOW"),
        source_ip=incident.get("source_ip") or "",
        description=desc,
        workflow_run_id=workflow_run_id or "",
        run_metadata=run_metadata or "",
    )


def push_incidents_grpc(
    incidents: list[dict],
    host: str,
    api_key: str | None = None,
    timeout: float = 10.0,
    workflow_run_id: str | None = None,
    run_metadata: dict | None = None,
) -> tuple[int, list[str]]:
    """Send each incident to the Go ingest-service via gRPC.

    Returns (success_count, error_messages). A missing grpcio package is
    reported as an error rather than an ImportError so the caller can log it
    and fall through to the REST path without crashing.

    ``host`` must be in ``host:port`` form, e.g. ``localhost:9001``.
    """
    try:
        import grpc
        from proto.ingest_pb2_grpc import AlertIngestServiceStub  # type: ignore[import]
    except ImportError as exc:
        return 0, [f"grpcio not installed — cannot use --soc-grpc-host ({exc}); "
                   "pip install grpcio"]

    import json
    meta_json = json.dumps(run_metadata) if run_metadata else None

    ok, errors = 0, []
    metadata = inject_grpc_metadata([("x-api-key", api_key)] if api_key else [])

    try:
        channel = grpc.insecure_channel(host)
        stub = AlertIngestServiceStub(channel)
        for inc in incidents:
            req = _incident_to_request(inc, workflow_run_id, meta_json)
            try:
                stub.IngestAlert(req, metadata=metadata, timeout=timeout)
                ok += 1
            except grpc.RpcError as exc:
                errors.append(f"gRPC {exc.code()}: {exc.details()}")
    except Exception as exc:  # noqa: BLE001
        errors.append(f"gRPC channel error: {exc}")
    finally:
        try:
            channel.close()
        except Exception:  # noqa: BLE001
            pass

    return ok, errors
