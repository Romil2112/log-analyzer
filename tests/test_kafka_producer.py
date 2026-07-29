"""Unit tests for kafka/producer.py (confluent-kafka Producer mocked)."""
import json
import os
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from kafka.producer import TOPIC, _serialize, publish_incidents


# ---------------------------------------------------------------------------
# _serialize helpers
# ---------------------------------------------------------------------------

def test_serialize_converts_datetime_to_iso():
    dt = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    result = json.loads(_serialize({"ts": dt}))
    assert result["ts"] == "2024-06-01T12:00:00+00:00"


def test_serialize_returns_bytes():
    data = _serialize({"incident_type": "brute_force"})
    assert isinstance(data, bytes)


def test_serialize_raises_on_nonserializable_type():
    with pytest.raises(TypeError):
        _serialize({"value": object()})


# ---------------------------------------------------------------------------
# publish_incidents — no-op and config
# ---------------------------------------------------------------------------

def test_publish_empty_list_returns_zero_no_errors():
    ok, errors = publish_incidents([], broker="localhost:9092")
    assert ok == 0
    assert errors == []


def test_publish_uses_default_topic():
    mock_producer = MagicMock()
    mock_producer.flush.return_value = 0

    with patch("kafka.producer.Producer", return_value=mock_producer):
        publish_incidents([{"incident_type": "brute_force"}], broker="localhost:9092")

    args, _ = mock_producer.produce.call_args
    assert args[0] == TOPIC


def test_publish_respects_custom_topic():
    mock_producer = MagicMock()
    mock_producer.flush.return_value = 0

    with patch("kafka.producer.Producer", return_value=mock_producer):
        publish_incidents(
            [{"incident_type": "port_scan"}],
            broker="localhost:9092",
            topic="custom_incidents",
        )

    args, _ = mock_producer.produce.call_args
    assert args[0] == "custom_incidents"


def test_publish_calls_produce_once_per_incident():
    mock_producer = MagicMock()
    mock_producer.flush.return_value = 0

    with patch("kafka.producer.Producer", return_value=mock_producer):
        publish_incidents(
            [
                {"incident_type": "brute_force", "source_ip": "1.2.3.4"},
                {"incident_type": "port_scan", "source_ip": "5.6.7.8"},
            ],
            broker="localhost:9092",
        )

    assert mock_producer.produce.call_count == 2


def test_publish_encodes_incident_as_json_bytes():
    mock_producer = MagicMock()
    mock_producer.flush.return_value = 0

    with patch("kafka.producer.Producer", return_value=mock_producer):
        publish_incidents(
            [{"incident_type": "brute_force", "source_ip": "10.0.0.1"}],
            broker="localhost:9092",
        )

    _, kwargs = mock_producer.produce.call_args
    body = json.loads(kwargs["value"])
    assert body["incident_type"] == "brute_force"
    assert body["source_ip"] == "10.0.0.1"


# ---------------------------------------------------------------------------
# Delivery callback counting
# ---------------------------------------------------------------------------

def _make_mock_producer_with_delivery(*, fail=False):
    """Return a mock Producer whose flush() fires on_delivery for each message."""
    mock_msg = MagicMock()
    mock_msg.topic.return_value = TOPIC
    mock_msg.partition.return_value = 0
    mock_error = MagicMock()
    mock_error.__str__ = lambda self: "simulated delivery failure"

    produced: list = []

    def capture_produce(topic, *, value, on_delivery):
        produced.append(on_delivery)

    def fake_flush(timeout):
        err = mock_error if fail else None
        for cb in produced:
            cb(err, mock_msg)
        return 0

    mock_producer = MagicMock()
    mock_producer.produce.side_effect = capture_produce
    mock_producer.flush.side_effect = fake_flush
    return mock_producer


def test_publish_counts_successful_deliveries():
    mock_producer = _make_mock_producer_with_delivery(fail=False)

    with patch("kafka.producer.Producer", return_value=mock_producer):
        ok, errors = publish_incidents(
            [{"incident_type": "brute_force"}, {"incident_type": "port_scan"}],
            broker="localhost:9092",
        )

    assert ok == 2
    assert errors == []


def test_publish_counts_delivery_failures():
    mock_producer = _make_mock_producer_with_delivery(fail=True)

    with patch("kafka.producer.Producer", return_value=mock_producer):
        ok, errors = publish_incidents(
            [{"incident_type": "brute_force"}],
            broker="localhost:9092",
        )

    assert ok == 0
    assert len(errors) == 1


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

def test_publish_handles_kafka_exception_on_init():
    from confluent_kafka import KafkaException

    with patch("kafka.producer.Producer", side_effect=KafkaException("no broker")):
        ok, errors = publish_incidents(
            [{"incident_type": "brute_force"}], broker="bad-host:9092"
        )

    assert ok == 0
    assert len(errors) == 1
    assert "Producer init failed" in errors[0]


def test_publish_handles_kafka_exception_on_produce():
    from confluent_kafka import KafkaException

    mock_producer = MagicMock()
    mock_producer.produce.side_effect = KafkaException("queue full")
    mock_producer.flush.return_value = 0

    with patch("kafka.producer.Producer", return_value=mock_producer):
        ok, errors = publish_incidents(
            [{"incident_type": "brute_force"}], broker="localhost:9092"
        )

    assert ok == 0
    assert any("produce error" in e for e in errors)


def test_publish_reports_undelivered_after_flush_timeout():
    mock_producer = MagicMock()
    mock_producer.flush.return_value = 2  # 2 messages not delivered

    with patch("kafka.producer.Producer", return_value=mock_producer):
        ok, errors = publish_incidents(
            [{"incident_type": "brute_force"}, {"incident_type": "port_scan"}],
            broker="localhost:9092",
        )

    assert any("undelivered after flush timeout" in e for e in errors)
