"""Tests for the S3-triggered Lambda handler.

boto3 and the analysis pipeline are mocked throughout — no real AWS
credentials or running services are needed.

boto3 is not installed in the development venv (it's only needed at Lambda
runtime), so we inject a mock module into sys.modules before the handler
imports it.  patch("boto3.client") then works against that mock.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from unittest.mock import MagicMock, patch

# Inject a mock boto3 before any handler import resolves it.
_boto3_mock = MagicMock()
sys.modules.setdefault("boto3", _boto3_mock)


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _make_s3_event(bucket: str = "test-bucket", key: str = "logs/auth.log") -> dict:
    return {
        "Records": [{
            "eventSource": "aws:s3",
            "s3": {
                "bucket": {"name": bucket},
                "object": {"key": key},
            },
        }]
    }


def _fake_download(bucket: str, key: str, dest: str) -> None:
    """Write a minimal auth.log so parse_ssh_log doesn't crash."""
    with open(dest, "w") as f:
        f.write(
            "Jan  1 00:00:01 host sshd[1234]: "
            "Failed password for root from 10.0.0.1 port 22 ssh2\n"
        )


def _synthetic_events() -> list[dict]:
    return [{
        "source_ip": "10.0.0.1",
        "event_type": "failed_login",
        "event_time": datetime(2024, 1, 1, 0, 0, 1),
        "port": 22,
        "username": "root",
    }]


def _synthetic_incidents() -> list[dict]:
    return [{
        "incident_type": "brute_force",
        "source_ip": "10.0.0.1",
        "event_count": 6,
        "severity": "HIGH",
        "mitre": {"id": "T1110.001", "tactic": "Credential Access"},
    }]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_handler_returns_200_on_valid_event():
    with patch("boto3.client") as mock_boto, \
         patch("log_analyzer.detect_log_format", return_value="ssh"), \
         patch("log_analyzer.parse_ssh_log", return_value=_synthetic_events()), \
         patch("log_analyzer._run_rule_detection", return_value=_synthetic_incidents()):
        mock_boto.return_value.download_file.side_effect = _fake_download
        from log_lambda.handler import lambda_handler
        resp = lambda_handler(_make_s3_event(), None)
    assert resp["statusCode"] == 200
    body = json.loads(resp["body"])
    assert body["incidents"] == 1
    assert body["events"] == 1


def test_handler_returns_400_on_malformed_event():
    from log_lambda.handler import lambda_handler
    resp = lambda_handler({"Records": []}, None)
    assert resp["statusCode"] == 400


def test_handler_returns_400_on_missing_records():
    from log_lambda.handler import lambda_handler
    resp = lambda_handler({}, None)
    assert resp["statusCode"] == 400


def test_handler_returns_500_on_s3_download_failure():
    with patch("boto3.client") as mock_boto:
        mock_boto.return_value.download_file.side_effect = Exception("NoSuchKey")
        from log_lambda.handler import lambda_handler
        resp = lambda_handler(_make_s3_event(), None)
    assert resp["statusCode"] == 500


def test_handler_pushes_to_soc_when_url_set():
    with patch("boto3.client") as mock_boto, \
         patch("log_analyzer.detect_log_format", return_value="ssh"), \
         patch("log_analyzer.parse_ssh_log", return_value=_synthetic_events()), \
         patch("log_analyzer._run_rule_detection", return_value=_synthetic_incidents()), \
         patch("soc_push.push_incidents", return_value=(1, [])) as mock_push, \
         patch.dict(os.environ, {"SOC_ALERTS_URL": "http://localhost:8001/api/alerts",
                                  "SOC_ALERTS_API_KEY": "test-key"}):
        mock_boto.return_value.download_file.side_effect = _fake_download
        from log_lambda.handler import lambda_handler
        resp = lambda_handler(_make_s3_event(), None)
    assert resp["statusCode"] == 200
    assert json.loads(resp["body"])["pushed"] == 1
    mock_push.assert_called_once()


def test_handler_skips_push_when_no_soc_url():
    with patch("boto3.client") as mock_boto, \
         patch("log_analyzer.detect_log_format", return_value="ssh"), \
         patch("log_analyzer.parse_ssh_log", return_value=_synthetic_events()), \
         patch("log_analyzer._run_rule_detection", return_value=_synthetic_incidents()), \
         patch("soc_push.push_incidents") as mock_push, \
         patch.dict(os.environ, {}, clear=True):
        mock_boto.return_value.download_file.side_effect = _fake_download
        from log_lambda.handler import lambda_handler
        resp = lambda_handler(_make_s3_event(), None)
    mock_push.assert_not_called()
    assert json.loads(resp["body"])["pushed"] == 0
