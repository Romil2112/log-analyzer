"""
Push detected incidents to a SOC-Dashboard ingestion endpoint.

This is the bridge that turns log-analyzer (detection) and SOC-Dashboard
(triage) into one pipeline: Ingest -> Detect -> Triage -> Respond.
Uses only the standard library (no extra dependency).
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.parse
import urllib.request

_ALLOWED_SCHEMES = ("http", "https")

# log-analyzer incident_type -> SOC-Dashboard alert category
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


__all__ = ["incident_to_alert", "push_incidents"]


def incident_to_alert(incident: dict) -> dict:
    """Map a log-analyzer incident to a SOC-Dashboard alert payload."""
    itype = incident.get("incident_type", "incident")
    ip    = incident.get("source_ip") or "unknown"
    mitre = incident.get("mitre", {}) or {}
    title = _TITLE.get(itype, f"{itype.replace('_', ' ').title()} from {{ip}}").format(ip=ip)
    desc  = (
        f"{incident.get('event_count', 0)} events; "
        f"MITRE {mitre.get('id', '-')} ({mitre.get('tactic', '-')})."
    )
    return {
        "title":       title,
        "category":    _CATEGORY.get(itype, "anomaly"),
        "severity":    incident.get("severity", "LOW"),
        "source_ip":   incident.get("source_ip"),
        "description": desc,
    }


def push_incidents(
    incidents: list[dict],
    url: str,
    api_key: str | None = None,
    timeout: float = 10.0,
) -> tuple[int, list[str]]:
    """POST each incident as an alert. Returns (success_count, error_messages).

    SOC-Dashboard's ``POST /api/alerts`` requires a matching ``X-API-Key`` header
    (its ``ALERTS_API_KEY``); pass it via ``api_key`` or the request will 401.

    Raises:
        ValueError: if ``url`` does not use an ``http``/``https`` scheme. This
            guards ``urllib.request.urlopen`` against ``file:``/custom schemes
            (bandit B310) so a crafted DSN cannot read local files.
    """
    scheme = urllib.parse.urlparse(url).scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise ValueError(
            f"refusing to push to non-HTTP(S) URL scheme {scheme!r}: {url!r}"
        )
    if url.startswith("http://"):
        # Warn but do not block (localhost/dev is fine over HTTP).
        print(
            "[!] WARNING: pushing over plaintext HTTP — source IPs and usernames "
            "will be transmitted unencrypted. Use HTTPS in production.",
            file=sys.stderr,
        )
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key
    ok, errors = 0, []
    for inc in incidents:
        data = json.dumps(incident_to_alert(inc)).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, method="POST", headers=headers,
        )
        try:
            # url scheme validated to http/https above (see push_incidents guard)
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
                if 200 <= resp.status < 300:
                    ok += 1
                else:
                    errors.append(f"HTTP {resp.status}")
        except urllib.error.URLError as exc:
            errors.append(str(exc))
    return ok, errors
