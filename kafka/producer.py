"""Kafka producer: publish detected incidents to the 'incidents' topic."""
import json
import logging
from datetime import datetime

from confluent_kafka import KafkaException, Producer

logger = logging.getLogger(__name__)

TOPIC = "incidents"


def _serialize(incident: dict) -> bytes:
    """JSON-encode an incident dict, converting datetime values to ISO strings."""
    def _default(obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"not serializable: {type(obj)!r}")
    return json.dumps(incident, default=_default).encode("utf-8")


def publish_incidents(
    incidents: list[dict],
    broker: str,
    topic: str = TOPIC,
) -> tuple[int, list[str]]:
    """Publish each incident as a JSON message to the Kafka topic.

    Returns (delivered_count, error_messages). Best-effort: a broker outage
    never aborts the analysis run — errors are collected and returned instead.

    Delivery is confirmed via the confluent-kafka on_delivery callback, which
    fires during the final flush(). remaining > 0 after the flush timeout is
    also reported as an error.
    """
    if not incidents:
        return 0, []

    delivered: list[int] = []
    errors: list[str] = []

    def _on_delivery(err, msg):
        if err:
            errors.append(f"{msg.topic()}[{msg.partition()}]: {err}")
        else:
            delivered.append(1)

    try:
        producer = Producer({
            "bootstrap.servers": broker,
            "socket.timeout.ms": 5000,
            "message.timeout.ms": 10000,
        })
    except KafkaException as exc:
        return 0, [f"Producer init failed: {exc}"]

    for incident in incidents:
        try:
            producer.produce(topic, value=_serialize(incident), on_delivery=_on_delivery)
        except (KafkaException, BufferError) as exc:
            errors.append(f"produce error: {exc}")

    remaining = producer.flush(timeout=10.0)
    if remaining > 0:
        errors.append(f"{remaining} message(s) undelivered after flush timeout")

    return len(delivered), errors
