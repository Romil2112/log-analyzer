"""
Elasticsearch incident indexing for log-analyzer.

Indexes detected incidents into an Elasticsearch index so the full SIEM
pipeline — detect → enrich → index → search — runs end-to-end. Optional:
controlled by --es-host. When the host is unset or unreachable the rest of
the pipeline continues unaffected.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

_INDEX = "log_analyzer_incidents"

_MAPPING: dict[str, Any] = {
    "mappings": {
        "properties": {
            "incident_type":  {"type": "keyword"},
            "source_ip":      {"type": "ip"},
            "country":        {"type": "keyword"},
            "severity":       {"type": "keyword"},
            "event_count":    {"type": "integer"},
            "known_bad":      {"type": "boolean"},
            "technique_id":   {"type": "keyword"},
            "technique_name": {"type": "keyword"},
            "tactic":         {"type": "keyword"},
            "log_file":       {"type": "keyword"},
            "indexed_at":     {"type": "date"},
        }
    }
}


def connect(host: str):
    """Return an Elasticsearch client for *host*, or None if unavailable.

    The caller never needs to handle ImportError or connection failures —
    this function absorbs both and returns None so the pipeline degrades
    gracefully when Elasticsearch is not configured.
    """
    try:
        from elasticsearch import Elasticsearch
    except ImportError:
        logger.warning("elasticsearch package not installed; skipping ES indexing")
        return None

    try:
        client = Elasticsearch(host, request_timeout=5)
        client.info()
        return client
    except Exception as exc:
        logger.warning("Elasticsearch unreachable at %s: %s", host, exc)
        return None


def ensure_index(client, index: str = _INDEX) -> None:
    """Create *index* with the incidents mapping if it does not already exist."""
    if client is None:
        return
    try:
        if not client.indices.exists(index=index):
            client.indices.create(index=index, body=_MAPPING)
    except Exception as exc:
        logger.warning("Could not ensure ES index '%s': %s", index, exc)


def index_incidents(
    client,
    incidents: list[dict],
    log_file: str = "",
    index: str = _INDEX,
) -> int:
    """Bulk-index *incidents* into *index*. Returns the count successfully indexed.

    Each incident document is enriched with the log file path and an indexed_at
    timestamp before being sent. Failures are logged per-document; the function
    never raises so the pipeline can continue even if ES goes down mid-run.
    """
    if client is None or not incidents:
        return 0

    from elasticsearch.helpers import BulkIndexError, bulk

    now = datetime.now(timezone.utc).isoformat()

    def _actions():
        for inc in incidents:
            mitre = inc.get("mitre") or {}
            yield {
                "_index": index,
                "_source": {
                    "incident_type":  inc.get("incident_type", "unknown"),
                    "source_ip":      inc.get("source_ip", ""),
                    "country":        inc.get("country", "Unknown"),
                    "severity":       inc.get("severity", "LOW"),
                    "event_count":    inc.get("event_count", 0),
                    "known_bad":      bool(inc.get("known_bad", False)),
                    "technique_id":   mitre.get("id", ""),
                    "technique_name": mitre.get("name", ""),
                    "tactic":         mitre.get("tactic", ""),
                    "log_file":       log_file,
                    "indexed_at":     now,
                },
            }

    try:
        success, _ = bulk(client, _actions(), raise_on_error=False)
        return success
    except BulkIndexError as exc:
        logger.warning("ES bulk index partial failure: %d error(s)", len(exc.errors))
        return len(incidents) - len(exc.errors)
    except Exception as exc:
        logger.warning("ES indexing failed: %s", exc)
        return 0
