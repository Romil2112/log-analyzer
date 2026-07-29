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

from export_util import unique_incident_types

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


__all__ = [
    "incident_to_sigma", "export_sigma",
    "generate_sigma_rule_llm", "export_sigma_llm",
]


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
    written = []
    for itype in unique_incident_types(incidents):
        rule = incident_to_sigma(itype)
        if rule is None:
            continue
        path = out / f"{itype}.yml"
        path.write_text(yaml.safe_dump(rule, sort_keys=False))
        written.append(str(path))
    return written


def generate_sigma_rule_llm(incident: dict, client) -> dict | None:
    """Generate a context-aware Sigma rule for an incident via the Claude API.

    Returns a validated rule dict on success, or None if the API call fails,
    the response is not parseable YAML, or required Sigma fields are missing.
    """
    mitre = incident.get("mitre", {})
    prompt = (
        f"Generate a Sigma detection rule for this security incident:\n"
        f"- Type: {incident['incident_type']}\n"
        f"- MITRE technique: {mitre.get('id', '?')} — {mitre.get('name', '')}\n"
        f"- Tactic: {mitre.get('tactic', '')}\n"
        f"- Observed event count: {incident['event_count']}\n"
        f"- Severity: {incident.get('severity', '?')}\n\n"
        "Return ONLY the Sigma rule as valid YAML. No explanations, no markdown "
        "fences. Required fields: title, id (UUID v4), status, description, "
        "author, date, tags (ATT&CK technique), logsource, detection, "
        "falsepositives, level."
    )
    try:
        msg = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=600,
            messages=[{"role": "user", "content": prompt}],
        )
    except Exception:  # noqa: BLE001
        return None
    if not getattr(msg, "content", None):
        return None
    raw = msg.content[0].text.strip()
    # Strip markdown code fences if the model wrapped the YAML anyway.
    if raw.startswith("```"):
        lines = raw.split("\n")
        raw = "\n".join(lines[1:])
        if raw.rstrip().endswith("```"):
            raw = raw.rstrip()[:-3]
    try:
        rule = yaml.safe_load(raw)
    except yaml.YAMLError:
        return None
    if not isinstance(rule, dict):
        return None
    if not all(k in rule for k in ("title", "detection", "logsource")):
        return None
    return rule


def export_sigma_llm(incidents: list[dict], out_dir: str, client) -> list[str]:
    """Generate LLM-powered Sigma rules for each observed incident type.

    Writes <type>_llm.yml per distinct type. Skips types whose rule generation
    fails. Returns the list of file paths written.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for itype in unique_incident_types(incidents):
        incident = next(i for i in incidents if i.get("incident_type") == itype)
        rule = generate_sigma_rule_llm(incident, client)
        if rule is None:
            continue
        path = out / f"{itype}_llm.yml"
        path.write_text(yaml.safe_dump(rule, sort_keys=False))
        written.append(str(path))
    return written
