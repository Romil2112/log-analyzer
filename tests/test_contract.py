"""Tests for the producer/consumer event-type contract.

These lock in the invariant that caught the original silent failure: a detector
that requires an event type no parser emits ("orphaned detector") must fail loud,
and the real pipeline's contract must stay healthy.
"""
import pytest

import contracts
from contracts import (
    ContractError,
    assert_event_contract,
    check_event_contract,
    produced_event_types,
)


def test_real_contract_is_healthy():
    # Every event-type-gated detector's required types are produced by a parser.
    assert check_event_contract() == []
    assert_event_contract()  # must not raise


def test_http_404_has_a_producer():
    # Regression guard for the original bug: detect_404_flood needs http_404,
    # and parse_web_log must keep producing it.
    assert "http_404" in produced_event_types()
    assert "http_404" in contracts.PARSER_EMITS["parse_web_log"]


def test_orphaned_detector_fails_loud():
    # A consumer with no producer is exactly the silent-failure shape; it must
    # be reported as a violation rather than silently accepted.
    requires = {**contracts.DETECTOR_REQUIRES, "detect_dns_tunnel": {"dns_query"}}
    violations = check_event_contract(detector_requires=requires)
    assert ("detect_dns_tunnel", ["dns_query"]) in violations


def test_orphaned_detector_raises():
    requires = {"detect_dns_tunnel": {"dns_query"}}
    with pytest.raises(ContractError) as exc:
        assert_event_contract(detector_requires=requires)
    assert "detect_dns_tunnel" in str(exc.value)
    assert "dns_query" in str(exc.value)


def test_removing_web_parser_orphans_404_detector():
    # If parse_web_log stopped emitting http_404 (the original regression),
    # detect_404_flood becomes orphaned and the check catches it.
    emits = {k: v for k, v in contracts.PARSER_EMITS.items() if k != "parse_web_log"}
    violations = check_event_contract(parser_emits=emits)
    assert any(d == "detect_404_flood" for d, _ in violations)
