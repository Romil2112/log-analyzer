"""
Export detected incidents as Sigma rules (detection-as-code).

Sigma (https://github.com/SigmaHQ/sigma) is the vendor-neutral standard for
writing detections. This converts each incident type produced by log-analyzer
into a Sigma rule YAML so the same logic can be shipped to a SIEM
(Splunk, Sentinel, Elastic) via the Sigma CLI.
"""
from __future__ import annotations

from pathlib import Path

import yaml

# Stable per-incident-type Sigma rule definitions, enriched with the same
# MITRE ATT&CK techniques the analyzer already maps.
_SIGMA_RULES: dict[str, dict] = {
    "brute_force": {
        "title": "SSH/Windows Brute-Force Authentication",
        "id": "0d8b1c2a-1111-4a1a-9c01-bruteforce0001",
        "description": "Repeated failed logins from a single source IP within a short window.",
        "level": "high",
        "logsource": {"category": "authentication"},
        "detection": {
            "selection": {"event_type": "failed_login"},
            "timeframe": "10m",
            "condition": "selection | count() by source_ip >= 5",
        },
        "tags": ["attack.credential_access", "attack.t1110.001"],
    },
    "port_scan": {
        "title": "Network Port Scan",
        "id": "0d8b1c2a-2222-4a1a-9c01-portscan0001",
        "description": "A single source IP contacting many distinct ports within a short window.",
        "level": "medium",
        "logsource": {"category": "network_connection"},
        "detection": {
            "selection": {"source_ip": "*"},
            "timeframe": "5m",
            "condition": "selection | count(port) by source_ip >= 20",
        },
        "tags": ["attack.discovery", "attack.t1046"],
    },
    "flood_404": {
        "title": "Web 404 Flood / Vulnerability Scanning",
        "id": "0d8b1c2a-3333-4a1a-9c01-flood4040001",
        "description": "A burst of HTTP 404 responses to one source IP, typical of content/vuln scanning.",
        "level": "medium",
        "logsource": {"category": "webserver"},
        "detection": {
            "selection": {"event_type": "http_404"},
            "timeframe": "5m",
            "condition": "selection | count() by source_ip >= 30",
        },
        "tags": ["attack.reconnaissance", "attack.t1595.002"],
    },
}


def incident_to_sigma(incident_type: str) -> dict | None:
    """Return the Sigma rule dict for an incident type (or None if unknown)."""
    rule = _SIGMA_RULES.get(incident_type)
    if rule is None:
        return None
    out = {"status": "experimental", "author": "log-analyzer"}
    out.update(rule)
    return out


def export_sigma(incidents: list[dict], out_dir: str) -> list[str]:
    """Write one Sigma .yml per *observed* incident type. Returns file paths."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    seen, written = set(), []
    for inc in incidents:
        itype = inc.get("incident_type")
        if itype in seen:
            continue
        rule = incident_to_sigma(itype)
        if rule is None:
            continue
        seen.add(itype)
        path = out / f"{itype}.yml"
        path.write_text(yaml.safe_dump(rule, sort_keys=False))
        written.append(str(path))
    return written
