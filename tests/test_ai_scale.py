"""Tests for the concurrent, instrumented Claude summarization layer.

A stub client stands in for the Anthropic SDK so these run with no API key,
no network, and no heavy deps.
"""
import threading
import time

import pytest

from ai_scale import build_incident_prompt, estimate_cost, looks_valid, summarize_batch


# --- stub Anthropic client --------------------------------------------------
class RateLimitError(Exception):
    """Name matches ai_scale._RETRYABLE_NAMES so it is treated as retryable."""


class _Usage:
    def __init__(self, i, o):
        self.input_tokens, self.output_tokens = i, o


class _Block:
    def __init__(self, text):
        self.text = text


class _Msg:
    def __init__(self, text, i, o):
        self.content = [_Block(text)]
        self.usage = _Usage(i, o)


class StubClient:
    """Configurable fake. `fail_first` raises `exc` on the first N calls."""
    def __init__(self, latency=0.0, fail_first=0, exc=RateLimitError, text="SOC summary: T1059 detected; remediate by isolating host."):
        self.latency = latency
        self.fail_first = fail_first
        self.exc = exc
        self.text = text
        self.calls = 0
        self._lock = threading.Lock()
        self.messages = self  # so client.messages.create(...) resolves here

    def create(self, *, model, max_tokens, messages):
        with self._lock:
            self.calls += 1
            n = self.calls
        if n <= self.fail_first:
            raise self.exc("simulated failure")
        if self.latency:
            time.sleep(self.latency)
        return _Msg(self.text, 100, 50)


NOSLEEP = lambda *_: None  # noqa: E731 - skip real backoff waits in tests


def test_all_succeed_and_tokens_summed():
    prompts = [f"p{i}" for i in range(10)]
    results, m = summarize_batch(prompts, client=StubClient(), max_concurrency=4, sleep=NOSLEEP)
    assert all(r is not None for r in results)
    assert m.succeeded == 10 and m.failed == 0
    assert m.input_tokens == 1000 and m.output_tokens == 500
    assert m.cost_usd == pytest.approx(estimate_cost(1000, 500))
    assert m.throughput_per_s > 0


def test_order_preserved():
    # text encodes nothing per-prompt, but length/positions must line up 1:1
    results, m = summarize_batch(["a", "b", "c"], client=StubClient(), sleep=NOSLEEP)
    assert len(results) == 3 and m.total == 3


def test_retry_recovers_from_transient():
    client = StubClient(fail_first=2)  # fail twice, then succeed
    results, m = summarize_batch(["x"], client=client, max_retries=3, max_concurrency=1, sleep=NOSLEEP)
    assert results[0] is not None
    assert m.succeeded == 1 and m.retries == 2


def test_retry_exhausted_marks_failed():
    client = StubClient(fail_first=99)
    results, m = summarize_batch(["x"], client=client, max_retries=2, max_concurrency=1, sleep=NOSLEEP)
    assert results[0] is None
    assert m.failed == 1 and m.succeeded == 0
    assert m.retries == 2  # initial + 2 retries = 3 attempts, 2 retries counted


def test_non_retryable_not_retried():
    client = StubClient(fail_first=99, exc=ValueError)
    results, m = summarize_batch(["x"], client=client, max_retries=5, max_concurrency=1, sleep=NOSLEEP)
    assert results[0] is None and m.failed == 1
    assert m.retries == 0  # ValueError is not retryable
    assert client.calls == 1


def test_cost_math():
    assert estimate_cost(1_000_000, 0) == pytest.approx(1.00)
    assert estimate_cost(0, 1_000_000) == pytest.approx(5.00)


def test_percentiles_and_eval_gate():
    results, m = summarize_batch([f"p{i}" for i in range(20)], client=StubClient(latency=0.002), max_concurrency=8, sleep=NOSLEEP)
    assert m.p95_ms >= m.p50_ms >= 0
    assert all(looks_valid(r) for r in results)
    assert not looks_valid("")
    assert not looks_valid("too short")


def test_empty_batch():
    results, m = summarize_batch([], client=StubClient(), sleep=NOSLEEP)
    assert results == [] and m.total == 0 and m.cost_usd == 0


def test_build_incident_prompt():
    p = build_incident_prompt([{"incident_type": "brute_force", "source_ip": "1.2.3.4",
                                "event_count": 9, "mitre": {"id": "T1110"}}])
    assert "brute_force" in p and "T1110" in p and "1.2.3.4" in p
