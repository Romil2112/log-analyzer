"""
ATT&CK Navigator layer export for log-analyzer.

Converts detected incidents to a Navigator 4.9 layer JSON that can be imported
at https://mitre-attack.github.io/attack-navigator/.
"""
from __future__ import annotations

import json
from pathlib import Path

# Navigator score by incident severity. Techniques with multiple incidents
# keep the highest score observed.
_SEVERITY_SCORE: dict[str, int] = {
    "CRITICAL": 100,
    "HIGH":     75,
    "MEDIUM":   50,
    "LOW":      25,
}

__all__ = ["build_navigator_layer", "export_navigator"]


def build_navigator_layer(
    incidents: list[dict],
    name: str = "Log Analyzer Detection Run",
) -> dict:
    """Build an ATT&CK Navigator 4.9 layer dict from detected incidents.

    Each distinct MITRE technique becomes one entry. When the same technique
    appears in multiple incidents, the entry takes the highest severity score.
    """
    techniques: dict[str, dict] = {}
    for inc in incidents:
        tid = inc.get("mitre", {}).get("id")
        if not tid:
            continue
        sev   = inc.get("severity", "LOW")
        score = _SEVERITY_SCORE.get(sev, 25)
        if tid not in techniques or score > techniques[tid]["score"]:
            techniques[tid] = {
                "techniqueID": tid,
                "score":       score,
                "color":       "",
                "comment":     (
                    f"{inc['incident_type']}: {inc['event_count']} events, {sev}"
                ),
                "enabled": True,
            }

    return {
        "name": name,
        "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (
            f"Detected {len(techniques)} ATT&CK technique(s) across "
            f"{len(incidents)} incident(s)."
        ),
        "techniques": list(techniques.values()),
        "gradient": {
            "colors":   ["#ffd700", "#ff6600", "#cc0000"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "CRITICAL (100)", "color": "#cc0000"},
            {"label": "HIGH (75)",      "color": "#ff6600"},
            {"label": "MEDIUM (50)",    "color": "#ffd700"},
            {"label": "LOW (25)",       "color": "#33cc66"},
        ],
        "showTacticRowBackground":      False,
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": True,
    }


def export_navigator(
    incidents: list[dict],
    out_dir: str,
    name: str = "Log Analyzer Detection Run",
) -> str:
    """Write an ATT&CK Navigator layer to out_dir/navigator_layer.json.

    Creates out_dir if it does not exist. Returns the path of the written file.
    """
    layer = build_navigator_layer(incidents, name=name)
    out   = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path  = out / "navigator_layer.json"
    path.write_text(json.dumps(layer, indent=2))
    return str(path)
