"""Tests for ai_agent.py — tool dispatch and the tool-use investigation loop.

All tests use a stub client; no real API key or network is required.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ai_agent import MAX_ROUNDS, _execute_tool, _first_text, run_investigation


# ---------------------------------------------------------------------------
# Stub Anthropic objects
# ---------------------------------------------------------------------------

class _TextBlock:
    type = "text"

    def __init__(self, text: str) -> None:
        self.text = text


class _ToolUseBlock:
    type = "tool_use"

    def __init__(self, tool_id: str, name: str, input_data: dict) -> None:
        self.id    = tool_id
        self.name  = name
        self.input = input_data


class _Response:
    def __init__(self, stop_reason: str, content: list) -> None:
        self.stop_reason = stop_reason
        self.content     = content


class SequenceClient:
    """Returns pre-configured responses in order; raises if exhausted early."""

    def __init__(self, responses: list) -> None:
        self._queue  = list(responses)
        self.calls   = 0
        self.messages = self  # client.messages.create(...)

    def create(self, **kwargs):
        self.calls += 1
        return self._queue.pop(0)


# ---------------------------------------------------------------------------
# Shared incident fixtures
# ---------------------------------------------------------------------------

INCIDENTS = [
    {
        "incident_type": "brute_force",
        "source_ip":     "10.0.0.1",
        "event_count":   150,
        "severity":      "HIGH",
        "mitre":         {"id": "T1110.001", "name": "Brute Force"},
        "known_bad":     True,
        "country":       "US",
    },
    {
        "incident_type": "port_scan",
        "source_ip":     "10.0.0.2",
        "event_count":   300,
        "severity":      "CRITICAL",
        "mitre":         {"id": "T1046", "name": "Network Service Discovery"},
        "known_bad":     False,
        "country":       "DE",
    },
    {
        "incident_type": "flood_404",
        "source_ip":     "10.0.0.3",
        "event_count":   80,
        "severity":      "MEDIUM",
        "mitre":         {"id": "T1595.002", "name": "Vulnerability Scanning"},
        "known_bad":     False,
        "country":       "",
    },
]


# ---------------------------------------------------------------------------
# _execute_tool — pure-function dispatch
# ---------------------------------------------------------------------------

def test_execute_tool_get_by_severity_critical():
    result = _execute_tool(
        "get_incidents_by_severity", {"severity": "CRITICAL"}, INCIDENTS, None
    )
    assert len(result) == 1
    assert result[0]["source_ip"] == "10.0.0.2"
    assert result[0]["mitre_id"] == "T1046"


def test_execute_tool_get_by_severity_empty():
    result = _execute_tool(
        "get_incidents_by_severity", {"severity": "LOW"}, INCIDENTS, None
    )
    assert result == []


def test_execute_tool_get_top_threat_sources_default_limit():
    result = _execute_tool("get_top_threat_sources", {}, INCIDENTS, None)
    # All three incidents, sorted by event_count descending
    assert result[0]["source_ip"] == "10.0.0.2"   # count=300
    assert result[1]["source_ip"] == "10.0.0.1"   # count=150
    assert result[2]["source_ip"] == "10.0.0.3"   # count=80


def test_execute_tool_get_top_threat_sources_custom_limit():
    result = _execute_tool("get_top_threat_sources", {"limit": 1}, INCIDENTS, None)
    assert len(result) == 1
    assert result[0]["source_ip"] == "10.0.0.2"


def test_execute_tool_get_top_threat_sources_bad_limit_defaults_to_5():
    result = _execute_tool("get_top_threat_sources", {"limit": "oops"}, INCIDENTS, None)
    assert isinstance(result, list)


def test_execute_tool_get_mitre_coverage():
    result = _execute_tool("get_mitre_coverage", {}, INCIDENTS, None)
    ids = {r["technique_id"] for r in result}
    assert "T1110.001" in ids
    assert "T1046" in ids
    assert "T1595.002" in ids
    # Each technique appears once in INCIDENTS, so each count is 1
    assert all(r["count"] == 1 for r in result)


def test_execute_tool_get_mitre_coverage_empty():
    result = _execute_tool("get_mitre_coverage", {}, [], None)
    assert result == []


def test_execute_tool_query_similar_ttps_no_conn():
    result = _execute_tool("query_similar_ttps", {"query": "brute force"}, INCIDENTS, None)
    assert result == []


def test_execute_tool_unknown_returns_error():
    result = _execute_tool("no_such_tool", {}, INCIDENTS, None)
    assert "error" in result


# ---------------------------------------------------------------------------
# _first_text helper
# ---------------------------------------------------------------------------

def test_first_text_finds_text_block():
    content = [_TextBlock("hello")]
    assert _first_text(content) == "hello"


def test_first_text_skips_tool_use_blocks():
    content = [_ToolUseBlock("id1", "some_tool", {}), _TextBlock("found")]
    assert _first_text(content) == "found"


def test_first_text_empty_returns_none():
    assert _first_text([]) is None


def test_first_text_no_text_blocks_returns_none():
    content = [_ToolUseBlock("id1", "tool", {})]
    assert _first_text(content) is None


# ---------------------------------------------------------------------------
# run_investigation — full loop with stub clients
# ---------------------------------------------------------------------------

def test_run_investigation_no_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert run_investigation(INCIDENTS) is None


def test_run_investigation_immediate_end_turn():
    client = SequenceClient([
        _Response("end_turn", [_TextBlock("Immediate report: all clear.")])
    ])
    result = run_investigation(INCIDENTS, client=client)
    assert result == "Immediate report: all clear."
    assert client.calls == 1


def test_run_investigation_single_tool_round():
    tool_call = _ToolUseBlock("tu-1", "get_mitre_coverage", {})
    client = SequenceClient([
        _Response("tool_use", [tool_call]),
        _Response("end_turn", [_TextBlock("Coverage analysed.")]),
    ])
    result = run_investigation(INCIDENTS, client=client)
    assert result == "Coverage analysed."
    assert client.calls == 2


def test_run_investigation_two_tool_rounds():
    t1 = _ToolUseBlock("tu-1", "get_top_threat_sources", {"limit": 3})
    t2 = _ToolUseBlock("tu-2", "get_incidents_by_severity", {"severity": "HIGH"})
    client = SequenceClient([
        _Response("tool_use", [t1]),
        _Response("tool_use", [t2]),
        _Response("end_turn", [_TextBlock("Two-round report done.")]),
    ])
    result = run_investigation(INCIDENTS, client=client)
    assert result == "Two-round report done."
    assert client.calls == 3


def test_run_investigation_max_rounds_triggers_forced_synthesis():
    """When the model always returns tool_use, max_rounds is respected and a
    final synthesis call (without tools in the response) is made."""
    always_tool = _ToolUseBlock("tu-x", "get_mitre_coverage", {})
    final_text  = "Forced synthesis complete."

    responses = (
        [_Response("tool_use", [always_tool])] * MAX_ROUNDS
        + [_Response("end_turn", [_TextBlock(final_text)])]
    )
    client = SequenceClient(responses)
    result = run_investigation(INCIDENTS, client=client, max_rounds=MAX_ROUNDS)
    # The loop runs MAX_ROUNDS times, then one final synthesis call = MAX_ROUNDS + 1
    assert result == final_text
    assert client.calls == MAX_ROUNDS + 1


def test_run_investigation_custom_max_rounds():
    tool_call = _ToolUseBlock("tu-1", "get_mitre_coverage", {})
    client    = SequenceClient([
        _Response("tool_use", [tool_call]),
        _Response("end_turn", [_TextBlock("done after 1 round")]),
    ])
    result = run_investigation(INCIDENTS, client=client, max_rounds=1)
    assert result == "done after 1 round"


def test_run_investigation_empty_incidents():
    client = SequenceClient([
        _Response("end_turn", [_TextBlock("No incidents to report.")])
    ])
    result = run_investigation([], client=client)
    assert result == "No incidents to report."


def test_run_investigation_returns_none_when_no_content():
    """If the final response has no text block, return None gracefully."""
    client = SequenceClient([
        _Response("end_turn", [])
    ])
    result = run_investigation(INCIDENTS, client=client)
    assert result is None


def test_run_investigation_tool_result_contains_valid_json():
    """Tool results sent back to the model must be valid JSON strings."""
    captured_messages = []

    class RecordingClient:
        calls    = 0
        messages = None

        def create(self, **kwargs):
            self.calls += 1
            captured_messages.extend(kwargs.get("messages", []))
            if self.calls == 1:
                return _Response("tool_use", [_ToolUseBlock("tu-1", "get_mitre_coverage", {})])
            return _Response("end_turn", [_TextBlock("done")])

    rc = RecordingClient()
    rc.messages = rc
    run_investigation(INCIDENTS, client=rc)

    # The third message is the user turn with tool_results
    tool_result_msg = next(
        m for m in captured_messages if m.get("role") == "user"
        and isinstance(m.get("content"), list)
        and m["content"] and m["content"][0].get("type") == "tool_result"
    )
    content_str = tool_result_msg["content"][0]["content"]
    parsed = json.loads(content_str)   # must not raise
    assert isinstance(parsed, list)    # get_mitre_coverage returns a list



def test_run_investigation_passes_explicit_timeout():
    """messages.create must be called with an explicit timeout= not the SDK default."""
    from unittest.mock import MagicMock

    fake_response = _Response("end_turn", [_TextBlock("summary")])
    fake_client = MagicMock()
    fake_client.messages.create.return_value = fake_response

    run_investigation(INCIDENTS, client=fake_client)

    _, kwargs = fake_client.messages.create.call_args
    assert "timeout" in kwargs, "messages.create must include an explicit timeout="
    assert isinstance(kwargs["timeout"], (int, float)) and kwargs["timeout"] <= 120
