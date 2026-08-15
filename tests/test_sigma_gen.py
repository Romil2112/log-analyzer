"""Tests for generate_sigma_rule_llm and export_sigma_llm in sigma_export.py.

Uses a stub client; no real API key or network required.
"""
import os
import sys
from pathlib import Path

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sigma_export import export_sigma_llm, generate_sigma_rule_llm

# ---------------------------------------------------------------------------
# Stub Anthropic client
# ---------------------------------------------------------------------------

class _Block:
    def __init__(self, text: str) -> None:
        self.text = text


class _Msg:
    def __init__(self, text: str) -> None:
        self.content = [_Block(text)]


class _EmptyMsg:
    content = []


class _StubMessages:
    def __init__(self, text: str) -> None:
        self._text = text

    def create(self, **kwargs) -> _Msg:
        return _Msg(self._text)


class StubClient:
    def __init__(self, text: str) -> None:
        self.messages = _StubMessages(text)


class EmptyContentClient:
    class _M:
        content = []
        def create(self, **kwargs): return _EmptyMsg()

    messages = _M()


class RaisingClient:
    class _M:
        def create(self, **kwargs): raise RuntimeError("API error")

    messages = _M()


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

VALID_SIGMA_YAML = """\
title: Brute Force Authentication Detection
id: 00000000-0000-4000-a000-000000000001
status: experimental
description: Detects repeated failed login attempts from a single source IP.
author: log-analyzer
date: 2024/01/01
tags:
  - attack.credential_access
  - attack.t1110.001
logsource:
  category: authentication
detection:
  selection:
    event_type: failed_login
  timeframe: 10m
  condition: selection | count() by source_ip >= 5
falsepositives:
  - Legitimate administrator activity
level: high
"""

INCIDENT = {
    "incident_type": "brute_force",
    "source_ip":     "1.2.3.4",
    "event_count":   50,
    "severity":      "HIGH",
    "mitre":         {"id": "T1110.001", "name": "Brute Force", "tactic": "Credential Access"},
}


# ---------------------------------------------------------------------------
# generate_sigma_rule_llm
# ---------------------------------------------------------------------------

def test_generate_valid_rule_returns_dict():
    rule = generate_sigma_rule_llm(INCIDENT, StubClient(VALID_SIGMA_YAML))
    assert isinstance(rule, dict)
    assert rule["title"] == "Brute Force Authentication Detection"


def test_generate_rule_has_required_fields():
    rule = generate_sigma_rule_llm(INCIDENT, StubClient(VALID_SIGMA_YAML))
    assert "title"     in rule
    assert "detection" in rule
    assert "logsource" in rule


def test_generate_strips_yaml_code_fence():
    fenced = "```yaml\n" + VALID_SIGMA_YAML + "```"
    rule   = generate_sigma_rule_llm(INCIDENT, StubClient(fenced))
    assert rule is not None
    assert rule["title"] == "Brute Force Authentication Detection"


def test_generate_strips_plain_code_fence():
    fenced = "```\n" + VALID_SIGMA_YAML + "```"
    rule   = generate_sigma_rule_llm(INCIDENT, StubClient(fenced))
    assert rule is not None


def test_generate_invalid_yaml_returns_none():
    rule = generate_sigma_rule_llm(INCIDENT, StubClient("this: is: not::valid: yaml:"))
    assert rule is None


def test_generate_non_dict_yaml_returns_none():
    rule = generate_sigma_rule_llm(INCIDENT, StubClient("- item1\n- item2\n"))
    assert rule is None


def test_generate_missing_title_returns_none():
    incomplete = "detection:\n  condition: true\nlogsource:\n  category: x\n"
    rule = generate_sigma_rule_llm(INCIDENT, StubClient(incomplete))
    assert rule is None


def test_generate_missing_detection_returns_none():
    incomplete = "title: Test\nlogsource:\n  category: x\n"
    rule = generate_sigma_rule_llm(INCIDENT, StubClient(incomplete))
    assert rule is None


def test_generate_missing_logsource_returns_none():
    incomplete = "title: Test\ndetection:\n  condition: true\n"
    rule = generate_sigma_rule_llm(INCIDENT, StubClient(incomplete))
    assert rule is None


def test_generate_api_exception_returns_none():
    rule = generate_sigma_rule_llm(INCIDENT, RaisingClient())
    assert rule is None


def test_generate_empty_content_returns_none():
    rule = generate_sigma_rule_llm(INCIDENT, EmptyContentClient())
    assert rule is None


# ---------------------------------------------------------------------------
# export_sigma_llm
# ---------------------------------------------------------------------------

def test_export_writes_file(tmp_path):
    paths = export_sigma_llm([INCIDENT], str(tmp_path), StubClient(VALID_SIGMA_YAML))
    assert len(paths) == 1
    assert Path(paths[0]).name == "brute_force_llm.yml"
    assert Path(paths[0]).exists()


def test_export_written_file_is_valid_yaml(tmp_path):
    paths = export_sigma_llm([INCIDENT], str(tmp_path), StubClient(VALID_SIGMA_YAML))
    loaded = yaml.safe_load(Path(paths[0]).read_text())
    assert isinstance(loaded, dict)
    assert "title" in loaded


def test_export_deduplicates_incident_types(tmp_path):
    incidents = [INCIDENT, {**INCIDENT, "source_ip": "9.9.9.9"}]
    paths = export_sigma_llm(incidents, str(tmp_path), StubClient(VALID_SIGMA_YAML))
    assert len(paths) == 1


def test_export_multiple_distinct_types(tmp_path):
    port_scan = {
        "incident_type": "port_scan",
        "source_ip":     "5.5.5.5",
        "event_count":   300,
        "severity":      "CRITICAL",
        "mitre":         {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    }
    paths = export_sigma_llm([INCIDENT, port_scan], str(tmp_path), StubClient(VALID_SIGMA_YAML))
    names = {Path(p).name for p in paths}
    assert "brute_force_llm.yml" in names
    assert "port_scan_llm.yml"   in names


def test_export_skips_failed_generation(tmp_path):
    paths = export_sigma_llm([INCIDENT], str(tmp_path), RaisingClient())
    assert paths == []


def test_export_creates_output_dir(tmp_path):
    out_dir = str(tmp_path / "new_dir")
    export_sigma_llm([INCIDENT], out_dir, StubClient(VALID_SIGMA_YAML))
    assert Path(out_dir).is_dir()


def test_export_empty_incidents_returns_empty(tmp_path):
    paths = export_sigma_llm([], str(tmp_path), StubClient(VALID_SIGMA_YAML))
    assert paths == []


# ---------------------------------------------------------------------------
# CLI flag wiring
# ---------------------------------------------------------------------------

def test_cli_flag_llm_sigma_parsed():
    import log_analyzer
    args = log_analyzer.build_parser().parse_args(
        ["dummy.log", "--llm-sigma", "/tmp/sigma_out"]
    )
    assert args.llm_sigma == "/tmp/sigma_out"


def test_cli_flag_llm_sigma_defaults_none():
    import log_analyzer
    args = log_analyzer.build_parser().parse_args(["dummy.log"])
    assert args.llm_sigma is None
