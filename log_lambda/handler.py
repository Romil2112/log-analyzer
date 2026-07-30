"""
Lambda handler: S3-triggered log analysis.

On each S3 ObjectCreated event, this handler downloads the log file to /tmp,
runs it through the existing parse → detect → anomaly-score pipeline, and
pushes the resulting incidents to a SOC-Dashboard endpoint if configured.

This module contains no detection logic of its own — it is a thin adapter
that wires the S3 event to the log-analyzer library code.

Environment variables:
    SOC_ALERTS_URL       POST /api/alerts endpoint on the SOC-Dashboard (optional)
    SOC_ALERTS_API_KEY   X-API-Key for the SOC-Dashboard ingest endpoint (optional)
"""
from __future__ import annotations

import json
import logging
import os
import sys
import urllib.parse

# Ensure the repo root is importable when SAM bundles with CodeUri pointing here.
_repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def lambda_handler(event: dict, context) -> dict:
    """Entry point for the S3-triggered Lambda function."""
    try:
        record = event["Records"][0]["s3"]
        bucket = record["bucket"]["name"]
        key    = urllib.parse.unquote_plus(record["object"]["key"])
    except (KeyError, IndexError) as exc:
        logger.error("malformed S3 event: %s", exc)
        return {"statusCode": 400, "body": "malformed S3 event"}

    import boto3  # optional dep — only needed at runtime in Lambda

    tmp_path = f"/tmp/{os.path.basename(key)}"
    try:
        boto3.client("s3").download_file(bucket, key, tmp_path)
    except Exception as exc:  # noqa: BLE001
        logger.error("S3 download failed: %s", exc)
        return {"statusCode": 500, "body": f"S3 download failed: {exc}"}

    try:
        from log_analyzer import (
            detect_log_format,
            parse_ssh_log,
            parse_web_log,
            parse_windows_csv,
            _run_rule_detection,
            enrich_incidents,
        )

        fmt = detect_log_format(tmp_path)
        if fmt == "ssh":
            events = parse_ssh_log(tmp_path)
        elif fmt == "web":
            events = parse_web_log(tmp_path)
        else:
            events = parse_windows_csv(tmp_path)

        incidents = _run_rule_detection(events)
    except Exception as exc:  # noqa: BLE001
        logger.error("analysis pipeline failed: %s", exc)
        return {"statusCode": 500, "body": f"analysis failed: {exc}"}
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    soc_url = os.getenv("SOC_ALERTS_URL", "")
    soc_key = os.getenv("SOC_ALERTS_API_KEY", "")
    pushed  = 0
    if soc_url and incidents:
        from soc_push import push_incidents
        pushed, errors = push_incidents(incidents, soc_url, api_key=soc_key or None)
        if errors:
            logger.warning("%d push error(s): %s", len(errors), errors[0])

    logger.info(
        "processed s3://%s/%s — %d events, %d incidents, %d pushed",
        bucket, key, len(events), len(incidents), pushed,
    )
    return {
        "statusCode": 200,
        "body": json.dumps({
            "bucket":    bucket,
            "key":       key,
            "events":    len(events),
            "incidents": len(incidents),
            "pushed":    pushed,
        }),
    }
