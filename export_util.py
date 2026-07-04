"""Shared helpers for the detection-as-code exporters.

Both ``sigma_export`` and ``siem_export`` walk the incident list, skipping
duplicate incident types, before writing one artifact per type. That dedup
scaffold lives here so neither exporter has to reimplement it.
"""
from __future__ import annotations

from collections.abc import Iterator

__all__ = ["unique_incident_types"]


def unique_incident_types(incidents: list[dict]) -> Iterator[str]:
    """Yield each distinct, non-empty ``incident_type`` once, in first-seen order.

    Args:
        incidents: Detected incidents (each a dict with an ``incident_type`` key).

    Yields:
        Each unique incident type string exactly once.
    """
    seen: set[str] = set()
    for inc in incidents:
        itype = inc.get("incident_type")
        if itype and itype not in seen:
            seen.add(itype)
            yield itype
