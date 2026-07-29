"""Tests for threat_intel_rag.py — STIX parsing, embedding storage, and RAG retrieval."""
import json
import os
import sys
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import threat_intel_rag as rag

# ---------------------------------------------------------------------------
# Minimal STIX bundle fixture — avoids dependency on the real ATT&CK download
# ---------------------------------------------------------------------------

# All IDs are valid RFC 4122 v4 UUIDs (version digit = 4, variant digit = 8/9/a/b).
_STIX_BUNDLE = {
    "type": "bundle",
    "id": "bundle--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    "objects": [
        {
            "type": "attack-pattern",
            "id": "attack-pattern--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "spec_version": "2.1",
            "created": "2021-01-01T00:00:00.000Z",
            "modified": "2021-01-01T00:00:00.000Z",
            "name": "Brute Force",
            "description": "Adversaries may use brute force techniques to gain access.",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1110",
                    "url": "https://attack.mitre.org/techniques/T1110",
                }
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}
            ],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--cccccccc-cccc-4ccc-9ccc-cccccccccccc",
            "spec_version": "2.1",
            "created": "2021-01-01T00:00:00.000Z",
            "modified": "2021-01-01T00:00:00.000Z",
            "name": "Network Service Discovery",
            "description": "Adversaries may attempt to get a listing of services running on remote hosts.",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1046",
                    "url": "https://attack.mitre.org/techniques/T1046",
                }
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "discovery"}
            ],
        },
        # Non-attack-pattern object — must be filtered out
        {
            "type": "relationship",
            "id": "relationship--dddddddd-dddd-4ddd-addd-dddddddddddd",
            "spec_version": "2.1",
            "created": "2021-01-01T00:00:00.000Z",
            "modified": "2021-01-01T00:00:00.000Z",
            "relationship_type": "uses",
            "source_ref": "attack-pattern--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "target_ref": "attack-pattern--cccccccc-cccc-4ccc-9ccc-cccccccccccc",
        },
        # attack-pattern with no mitre-attack external reference — must be skipped
        {
            "type": "attack-pattern",
            "id": "attack-pattern--eeeeeeee-eeee-4eee-beee-eeeeeeeeeeee",
            "spec_version": "2.1",
            "created": "2021-01-01T00:00:00.000Z",
            "modified": "2021-01-01T00:00:00.000Z",
            "name": "Some Other Technique",
            "description": "Not a MITRE technique.",
            "external_references": [
                {"source_name": "capec", "external_id": "CAPEC-001"}
            ],
        },
    ],
}


@pytest.fixture
def stix_file(tmp_path):
    p = tmp_path / "bundle.json"
    p.write_text(json.dumps(_STIX_BUNDLE))
    return str(p)


@pytest.fixture
def mock_model():
    """Patch the module-level lazy model so no real download occurs in tests."""
    fake = MagicMock()
    fake.embed.side_effect = lambda texts: iter(
        [np.ones(384, dtype=np.float32) * 0.1 for _ in texts]
    )
    with patch("threat_intel_rag._EMBEDDING_MODEL", fake):
        yield fake


@pytest.fixture
def mock_conn():
    conn = MagicMock()
    cur = MagicMock()
    conn.cursor.return_value.__enter__ = lambda s: cur
    conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
    cur.fetchall.return_value = [
        ("T1110", "Brute Force", "Credential Access",
         "Adversaries may use brute force techniques.", 0.92),
        ("T1046", "Network Service Discovery", "Discovery",
         "Adversaries may get a listing of services.", 0.85),
    ]
    return conn, cur


# ---------------------------------------------------------------------------
# load_stix_ttps
# ---------------------------------------------------------------------------

def test_load_stix_ttps_returns_only_attack_patterns(stix_file):
    ttps = rag.load_stix_ttps(stix_file)
    # relationship and no-ref attack-pattern must be excluded
    assert all(isinstance(t, dict) for t in ttps)
    ids = {t["technique_id"] for t in ttps}
    assert "T1110" in ids
    assert "T1046" in ids
    assert len(ids) == 2  # the relationship and capec-only objects are filtered


def test_load_stix_ttps_extracts_correct_fields(stix_file):
    ttps = {t["technique_id"]: t for t in rag.load_stix_ttps(stix_file)}
    bf = ttps["T1110"]
    assert bf["name"] == "Brute Force"
    assert "brute force" in bf["description"].lower()
    assert bf["technique_id"] == "T1110"


def test_load_stix_ttps_title_cases_tactic(stix_file):
    ttps = {t["technique_id"]: t for t in rag.load_stix_ttps(stix_file)}
    assert ttps["T1110"]["tactic"] == "Credential Access"
    assert ttps["T1046"]["tactic"] == "Discovery"


def test_load_stix_ttps_handles_missing_description(tmp_path):
    bundle = {
        "type": "bundle",
        "id": "bundle--ffffffff-ffff-4fff-8fff-ffffffffffff",
        "objects": [{
            "type": "attack-pattern",
            "id": "attack-pattern--11111111-1111-4111-8111-111111111111",
            "spec_version": "2.1",
            "created": "2021-01-01T00:00:00.000Z",
            "modified": "2021-01-01T00:00:00.000Z",
            "name": "No Description Technique",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T9999"}
            ],
        }],
    }
    p = tmp_path / "nodesc.json"
    p.write_text(json.dumps(bundle))
    ttps = rag.load_stix_ttps(str(p))
    assert ttps[0]["description"] == ""


# ---------------------------------------------------------------------------
# embed_and_store
# ---------------------------------------------------------------------------

def test_embed_and_store_returns_count(mock_model, mock_conn):
    conn, cur = mock_conn
    ttps = [
        {"technique_id": "T1110", "name": "Brute Force",
         "tactic": "Credential Access", "description": "desc"},
    ]
    result = rag.embed_and_store(conn, ttps)
    assert result == 1


def test_embed_and_store_calls_execute_for_each_ttp(mock_model, mock_conn):
    conn, cur = mock_conn
    ttps = [
        {"technique_id": "T1110", "name": "Brute Force",
         "tactic": "Credential Access", "description": "desc"},
        {"technique_id": "T1046", "name": "Network Service Discovery",
         "tactic": "Discovery", "description": "desc2"},
    ]
    rag.embed_and_store(conn, ttps)
    assert cur.execute.call_count == 2
    conn.commit.assert_called_once()


def test_embed_and_store_empty_input_returns_zero(mock_model, mock_conn):
    conn, cur = mock_conn
    assert rag.embed_and_store(conn, []) == 0
    cur.execute.assert_not_called()


# ---------------------------------------------------------------------------
# retrieve_context
# ---------------------------------------------------------------------------

def test_retrieve_context_returns_list_of_dicts(mock_model, mock_conn):
    conn, _ = mock_conn
    result = rag.retrieve_context(conn, ["brute force from 10.0.0.1"])
    assert isinstance(result, list)
    assert all("technique_id" in r and "name" in r for r in result)


def test_retrieve_context_empty_input_returns_empty(mock_model, mock_conn):
    conn, _ = mock_conn
    assert rag.retrieve_context(conn, []) == []


def test_retrieve_context_handles_db_error_gracefully(mock_model):
    conn = MagicMock()
    conn.cursor.side_effect = Exception("pgvector table missing")
    result = rag.retrieve_context(conn, ["some incident"])
    assert result == []


# ---------------------------------------------------------------------------
# format_context
# ---------------------------------------------------------------------------

def test_format_context_includes_technique_ids():
    ttps = [
        {"technique_id": "T1110", "name": "Brute Force",
         "tactic": "Credential Access", "description": "desc", "similarity": 0.9},
    ]
    out = rag.format_context(ttps)
    assert "T1110" in out
    assert "Credential Access" in out


def test_format_context_empty_returns_empty_string():
    assert rag.format_context([]) == ""


# ---------------------------------------------------------------------------
# CLI flag wiring
# ---------------------------------------------------------------------------

def test_cli_flag_threat_intel_stix_parsed():
    import log_analyzer
    args = log_analyzer.build_parser().parse_args(
        ["dummy.log", "--threat-intel-stix", "bundle.json"]
    )
    assert args.threat_intel_stix == "bundle.json"


def test_cli_flag_threat_intel_stix_defaults_none():
    import log_analyzer
    args = log_analyzer.build_parser().parse_args(["dummy.log"])
    assert args.threat_intel_stix is None
