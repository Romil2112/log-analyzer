"""Tests for the --gcs-bucket / _upload_to_gcs feature."""
import argparse
import os
import sys
import tempfile
import types
from unittest.mock import MagicMock, call

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from log_analyzer import _upload_to_gcs


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _args(bucket=None, report="incident_report.html"):
    ns = argparse.Namespace()
    ns.gcs_bucket = bucket
    ns.report = report
    return ns


def _install_mock_gcs(client_cls=None):
    """Install a mock google.cloud.storage module into sys.modules."""
    pkg = types.ModuleType("google.cloud.storage")
    pkg.Client = client_cls or MagicMock()
    sys.modules.setdefault("google", types.ModuleType("google"))
    sys.modules.setdefault("google.cloud", types.ModuleType("google.cloud"))
    sys.modules["google.cloud.storage"] = pkg
    return pkg


def _remove_mock_gcs():
    for key in list(sys.modules):
        if key.startswith("google"):
            del sys.modules[key]


# ---------------------------------------------------------------------------
# No-op paths
# ---------------------------------------------------------------------------

def test_no_bucket_is_noop(capsys):
    _upload_to_gcs("report.html", _args(bucket=None))
    assert capsys.readouterr().out == ""


def test_empty_bucket_string_is_noop(capsys):
    _upload_to_gcs("report.html", _args(bucket=""))
    assert capsys.readouterr().out == ""


# ---------------------------------------------------------------------------
# Missing dependency
# ---------------------------------------------------------------------------

def test_missing_package_prints_warning_and_does_not_raise(monkeypatch, capsys):
    _remove_mock_gcs()
    real_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__

    import builtins
    real_bi = builtins.__import__

    def _block(name, *args, **kwargs):
        if "google.cloud" in name:
            raise ImportError("no google-cloud-storage")
        return real_bi(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _block)
    _upload_to_gcs("report.html", _args(bucket="my-bucket"))
    out = capsys.readouterr().out
    assert "google-cloud-storage not installed" in out
    assert "pip install" in out


# ---------------------------------------------------------------------------
# Upload failures (graceful degradation)
# ---------------------------------------------------------------------------

def test_client_constructor_failure_warns_and_does_not_raise(capsys):
    _remove_mock_gcs()
    _install_mock_gcs(client_cls=MagicMock(side_effect=Exception("no credentials")))
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tf:
        tf.write(b"<html/>")
        tmp = tf.name
    try:
        _upload_to_gcs(tmp, _args(bucket="test-bucket", report=tmp))
    finally:
        os.unlink(tmp)
        _remove_mock_gcs()
    normalized = " ".join(capsys.readouterr().out.split())
    assert "GCS upload failed" in normalized
    assert "still available locally" in normalized


def test_upload_from_filename_failure_warns_and_does_not_raise(capsys):
    _remove_mock_gcs()
    mock_blob = MagicMock()
    mock_blob.upload_from_filename.side_effect = Exception("forbidden")
    mock_bucket = MagicMock()
    mock_bucket.blob.return_value = mock_blob
    mock_client = MagicMock()
    mock_client.bucket.return_value = mock_bucket
    _install_mock_gcs(client_cls=MagicMock(return_value=mock_client))
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tf:
        tf.write(b"<html/>")
        tmp = tf.name
    try:
        _upload_to_gcs(tmp, _args(bucket="test-bucket", report=tmp))
    finally:
        os.unlink(tmp)
        _remove_mock_gcs()
    out = capsys.readouterr().out
    assert "GCS upload failed" in out
    assert "still available locally" in out


def test_invalid_bucket_name_warns_and_does_not_raise(capsys):
    _remove_mock_gcs()
    _install_mock_gcs(
        client_cls=MagicMock(side_effect=Exception("Invalid bucket name: bad bucket"))
    )
    _upload_to_gcs("report.html", _args(bucket="bad bucket name!"))
    _remove_mock_gcs()
    out = capsys.readouterr().out
    assert "GCS upload failed" in out


# ---------------------------------------------------------------------------
# Success path
# ---------------------------------------------------------------------------

def test_success_calls_upload_from_filename_with_correct_path(capsys):
    _remove_mock_gcs()
    mock_blob = MagicMock()
    mock_bucket = MagicMock(return_value=MagicMock(blob=MagicMock(return_value=mock_blob)))
    mock_client = MagicMock()
    mock_client.bucket.return_value = mock_bucket.return_value
    _install_mock_gcs(client_cls=MagicMock(return_value=mock_client))

    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tf:
        tf.write(b"<html/>")
        tmp = tf.name
    try:
        _upload_to_gcs(tmp, _args(bucket="prod-bucket", report=tmp))
    finally:
        os.unlink(tmp)
        _remove_mock_gcs()

    mock_blob.upload_from_filename.assert_called_once_with(tmp)
    out = capsys.readouterr().out
    assert "prod-bucket" in out
    assert "Report uploaded" in out


def test_success_uses_filename_not_full_path_as_blob_name(capsys):
    """Blob name is the basename of the report path, not the full filesystem path."""
    _remove_mock_gcs()
    mock_blob = MagicMock()
    mock_client_inst = MagicMock()
    mock_client_inst.bucket.return_value.blob.return_value = mock_blob
    _install_mock_gcs(client_cls=MagicMock(return_value=mock_client_inst))

    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tf:
        tf.write(b"<html/>")
        tmp = tf.name
    try:
        _upload_to_gcs(tmp, _args(bucket="prod-bucket", report=tmp))
    finally:
        os.unlink(tmp)
        _remove_mock_gcs()

    blob_name_used = mock_client_inst.bucket.return_value.blob.call_args[0][0]
    expected = tmp.split("/")[-1]
    assert blob_name_used == expected


def test_success_passes_bucket_name_to_client(capsys):
    _remove_mock_gcs()
    mock_client_inst = MagicMock()
    _install_mock_gcs(client_cls=MagicMock(return_value=mock_client_inst))

    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tf:
        tf.write(b"<html/>")
        tmp = tf.name
    try:
        _upload_to_gcs(tmp, _args(bucket="specific-bucket", report=tmp))
    finally:
        os.unlink(tmp)
        _remove_mock_gcs()

    mock_client_inst.bucket.assert_called_once_with("specific-bucket")


# ---------------------------------------------------------------------------
# CLI flag wiring
# ---------------------------------------------------------------------------

def test_gcs_bucket_flag_is_registered():
    from log_analyzer import build_parser
    p = build_parser()
    args = p.parse_args(["dummy.log", "--gcs-bucket", "my-bucket"])
    assert args.gcs_bucket == "my-bucket"


def test_gcs_bucket_flag_defaults_to_none():
    from log_analyzer import build_parser
    p = build_parser()
    args = p.parse_args(["dummy.log"])
    assert args.gcs_bucket is None
