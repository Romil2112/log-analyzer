"""Tests for navigator_export.py — layer building and file export."""
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from navigator_export import build_navigator_layer, export_navigator

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

BF_INCIDENT = {
    "incident_type": "brute_force",
    "source_ip":     "1.2.3.4",
    "event_count":   150,
    "severity":      "CRITICAL",
    "mitre":         {"id": "T1110.001", "name": "Brute Force: Password Guessing"},
}

PS_INCIDENT = {
    "incident_type": "port_scan",
    "source_ip":     "5.6.7.8",
    "event_count":   300,
    "severity":      "HIGH",
    "mitre":         {"id": "T1046", "name": "Network Service Discovery"},
}

LOW_BF = {
    "incident_type": "brute_force",
    "source_ip":     "9.9.9.9",
    "event_count":   7,
    "severity":      "LOW",
    "mitre":         {"id": "T1110.001", "name": "Brute Force: Password Guessing"},
}


# ---------------------------------------------------------------------------
# build_navigator_layer
# ---------------------------------------------------------------------------

def test_empty_incidents_returns_empty_techniques():
    layer = build_navigator_layer([])
    assert layer["techniques"] == []


def test_single_critical_incident():
    layer = build_navigator_layer([BF_INCIDENT])
    assert len(layer["techniques"]) == 1
    t = layer["techniques"][0]
    assert t["techniqueID"] == "T1110.001"
    assert t["score"] == 100


def test_high_severity_scores_75():
    layer = build_navigator_layer([PS_INCIDENT])
    assert layer["techniques"][0]["score"] == 75


def test_low_severity_scores_25():
    low_inc = {**BF_INCIDENT, "severity": "LOW"}
    layer   = build_navigator_layer([low_inc])
    assert layer["techniques"][0]["score"] == 25


def test_medium_severity_scores_50():
    med_inc = {**BF_INCIDENT, "severity": "MEDIUM"}
    layer   = build_navigator_layer([med_inc])
    assert layer["techniques"][0]["score"] == 50


def test_max_score_wins_for_same_technique():
    """A CRITICAL and a LOW incident with the same technique ID → score 100."""
    layer = build_navigator_layer([LOW_BF, BF_INCIDENT])
    assert len(layer["techniques"]) == 1
    assert layer["techniques"][0]["score"] == 100


def test_multiple_distinct_techniques():
    layer = build_navigator_layer([BF_INCIDENT, PS_INCIDENT])
    ids   = {t["techniqueID"] for t in layer["techniques"]}
    assert "T1110.001" in ids
    assert "T1046"     in ids
    assert len(layer["techniques"]) == 2


def test_incident_with_no_mitre_id_is_skipped():
    no_mitre = {
        "incident_type": "unknown", "source_ip": "1.1.1.1",
        "event_count": 1, "severity": "LOW", "mitre": {},
    }
    layer = build_navigator_layer([no_mitre])
    assert layer["techniques"] == []


def test_incident_with_none_mitre_is_skipped():
    layer = build_navigator_layer([
        {"incident_type": "x", "source_ip": "1.1.1.1",
         "event_count": 1, "severity": "LOW", "mitre": {"id": None}}
    ])
    assert layer["techniques"] == []


def test_comment_includes_incident_type_and_severity():
    layer = build_navigator_layer([BF_INCIDENT])
    comment = layer["techniques"][0]["comment"]
    assert "brute_force" in comment
    assert "CRITICAL"    in comment


def test_layer_description_mentions_counts():
    layer = build_navigator_layer([BF_INCIDENT, PS_INCIDENT])
    assert "2" in layer["description"]


def test_layer_domain_is_enterprise_attack():
    layer = build_navigator_layer([])
    assert layer["domain"] == "enterprise-attack"


def test_layer_versions():
    layer = build_navigator_layer([])
    assert layer["versions"]["layer"]     == "4.5"
    assert layer["versions"]["navigator"] == "4.9"
    assert layer["versions"]["attack"]    == "14"


def test_layer_has_gradient():
    layer = build_navigator_layer([])
    g = layer["gradient"]
    assert g["minValue"] == 0
    assert g["maxValue"] == 100
    assert len(g["colors"]) >= 2


def test_layer_has_legend_items():
    layer = build_navigator_layer([])
    assert len(layer["legendItems"]) == 4
    labels = {item["label"] for item in layer["legendItems"]}
    assert any("CRITICAL" in lbl for lbl in labels)


def test_custom_layer_name():
    layer = build_navigator_layer([], name="My Custom Run")
    assert layer["name"] == "My Custom Run"


def test_techniques_have_enabled_true():
    layer = build_navigator_layer([BF_INCIDENT])
    assert layer["techniques"][0]["enabled"] is True


# ---------------------------------------------------------------------------
# export_navigator
# ---------------------------------------------------------------------------

def test_export_navigator_creates_file(tmp_path):
    path = export_navigator([BF_INCIDENT], str(tmp_path))
    assert Path(path).exists()
    assert Path(path).name == "navigator_layer.json"


def test_export_navigator_creates_dir(tmp_path):
    out_dir = str(tmp_path / "sub" / "dir")
    path    = export_navigator([BF_INCIDENT], out_dir)
    assert Path(path).exists()


def test_export_navigator_valid_json(tmp_path):
    path = export_navigator([BF_INCIDENT, PS_INCIDENT], str(tmp_path))
    data = json.loads(Path(path).read_text())
    assert "techniques" in data
    assert data["domain"] == "enterprise-attack"


def test_export_navigator_returns_path_string(tmp_path):
    result = export_navigator([], str(tmp_path))
    assert isinstance(result, str)
    assert result.endswith("navigator_layer.json")
