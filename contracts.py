"""Producer/consumer event-type contract for the detection pipeline.

The pipeline is producers (parsers) -> typed events -> consumers (detectors).
Each parser declares the ``event_type`` values it can emit; each event-type-gated
detector declares the types it requires. ``check_event_contract`` asserts that
every required type has at least one producer.

This exists because of a real silent failure: ``detect_404_flood`` consumes
``http_404`` events, but for a while no parser emitted them, so the detector ran
every analysis and produced nothing — no error, no warning, just an empty result.
This turns that class of bug ("a consumer with no producer") into a loud failure
at startup/CI instead of a silent no-op in production.

NOTE: ``detect_port_scan`` is intentionally absent — it is field-gated (it needs a
``port`` field), not ``event_type``-gated, so it is not part of the type contract.
"""

# event_type values each parser can emit
PARSER_EMITS = {
    "parse_ssh_log":     {"failed_login", "successful_login"},
    "parse_windows_csv": {"failed_login", "successful_login"},
    "parse_web_log":     {"http_404", "http_request"},
}

# event_type values each event-type-gated detector requires
DETECTOR_REQUIRES = {
    "detect_brute_force": {"failed_login"},
    "detect_404_flood":   {"http_404"},
}


__all__ = [
    "ContractError", "produced_event_types",
    "check_event_contract", "assert_event_contract",
]


class ContractError(RuntimeError):
    """Raised when a detector requires an event type no parser produces."""


def produced_event_types(parser_emits=None):
    out = set()
    for types in (parser_emits or PARSER_EMITS).values():
        out |= types
    return out


def check_event_contract(parser_emits=None, detector_requires=None):
    """Return a list of ``(detector, [missing_types])`` violations.

    An empty list means every detector's required event types are produced by
    at least one parser (a healthy contract).
    """
    emits = produced_event_types(parser_emits)
    violations = []
    for detector, required in (detector_requires or DETECTOR_REQUIRES).items():
        missing = required - emits
        if missing:
            violations.append((detector, sorted(missing)))
    return violations


def assert_event_contract(parser_emits=None, detector_requires=None):
    """Raise ContractError (fail loud) if any detector is orphaned."""
    violations = check_event_contract(parser_emits, detector_requires)
    if violations:
        detail = "; ".join(
            f"{d} requires {m} but no parser emits {'it' if len(m) == 1 else 'them'}"
            for d, m in violations
        )
        raise ContractError(f"Event-type contract violated: {detail}")
