"""
Multi-step agentic incident investigation via Claude tool use.

Calls up to MAX_ROUNDS tool-use rounds. If the model exhausts the cap without
reaching end_turn, a final synthesis call (no tools) forces a conclusion.
"""
from __future__ import annotations

import json
import logging
import os

logger = logging.getLogger(__name__)

MODEL = "claude-haiku-4-5-20251001"
MAX_ROUNDS = 5

_TOOLS: list[dict] = [
    {
        "name": "get_incidents_by_severity",
        "description": "Filter the detected incidents by severity level.",
        "input_schema": {
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    "description": "Severity level to filter by.",
                }
            },
            "required": ["severity"],
        },
    },
    {
        "name": "get_top_threat_sources",
        "description": "Return attacker IPs ranked by event count.",
        "input_schema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Maximum IPs to return (default 5).",
                }
            },
            "required": [],
        },
    },
    {
        "name": "get_mitre_coverage",
        "description": "List observed MITRE ATT&CK techniques and their incident counts.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "query_similar_ttps",
        "description": (
            "Find ATT&CK TTPs semantically similar to a query string via pgvector. "
            "Returns an empty list when pgvector is unavailable."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Incident description to find similar TTPs for.",
                }
            },
            "required": ["query"],
        },
    },
]

__all__ = ["run_investigation", "MAX_ROUNDS"]


def _execute_tool(
    name: str,
    tool_input: dict,
    incidents: list[dict],
    conn,
) -> object:
    """Dispatch one tool call and return a JSON-serialisable result."""
    if name == "get_incidents_by_severity":
        sev = tool_input.get("severity", "").upper()
        return [
            {
                "incident_type": i["incident_type"],
                "source_ip": i["source_ip"],
                "event_count": i["event_count"],
                "mitre_id": i.get("mitre", {}).get("id", ""),
            }
            for i in incidents
            if i.get("severity", "").upper() == sev
        ]

    if name == "get_top_threat_sources":
        try:
            limit = max(1, int(tool_input.get("limit", 5)))
        except (TypeError, ValueError):
            limit = 5
        ranked = sorted(incidents, key=lambda x: x.get("event_count", 0), reverse=True)
        return [
            {
                "source_ip": i["source_ip"],
                "incident_type": i["incident_type"],
                "event_count": i["event_count"],
                "severity": i.get("severity", ""),
                "known_bad": i.get("known_bad", False),
                "country": i.get("country", ""),
            }
            for i in ranked[:limit]
        ]

    if name == "get_mitre_coverage":
        coverage: dict[str, dict] = {}
        for i in incidents:
            tid = i.get("mitre", {}).get("id") or "unknown"
            if tid not in coverage:
                coverage[tid] = {"name": i.get("mitre", {}).get("name", ""), "count": 0}
            coverage[tid]["count"] += 1
        return [
            {"technique_id": k, "name": v["name"], "count": v["count"]}
            for k, v in sorted(coverage.items(), key=lambda x: -x[1]["count"])
        ]

    if name == "query_similar_ttps":
        if conn is None:
            return []
        try:
            from threat_intel_rag import retrieve_context
            return retrieve_context(conn, [tool_input.get("query", "")], top_k=3)
        except Exception as exc:  # noqa: BLE001
            logger.warning("TTP query failed: %s", exc)
            return []

    return {"error": f"unknown tool: {name}"}


def _first_text(content) -> str | None:
    """Return the text of the first TextBlock in content, or None."""
    for block in content:
        if hasattr(block, "text"):
            return block.text
    return None


def run_investigation(
    incidents: list[dict],
    conn=None,
    client=None,
    max_rounds: int = MAX_ROUNDS,
) -> str | None:
    """Run a multi-step Claude tool-use investigation on the given incidents.

    Each tool-use round: model calls tools → tools execute → results fed back.
    After max_rounds tool-use rounds (or when the model stops using tools), a
    final synthesis call without tools produces the investigation report.

    Returns the report text, or None if ANTHROPIC_API_KEY is unset.
    """
    if client is None:
        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            return None
        from anthropic import Anthropic
        client = Anthropic(api_key=key)

    inc_text = "\n".join(
        f"- {i['incident_type']} from {i['source_ip']}, "
        f"count={i['event_count']}, severity={i.get('severity', '?')}, "
        f"MITRE={i.get('mitre', {}).get('id', '?')}"
        for i in incidents
    )
    system_prompt = (
        "You are an expert SOC analyst investigating security incidents. "
        "Use the available tools to gather information, then write a concise "
        "investigation report covering: top threats, attacker profiles, "
        "MITRE ATT&CK coverage, and recommended immediate actions."
    )
    messages: list[dict] = [
        {"role": "user", "content": f"Investigate these incidents:\n{inc_text}"}
    ]

    for _ in range(max_rounds):
        response = client.messages.create(
            model=MODEL,
            max_tokens=1024,
            system=system_prompt,
            tools=_TOOLS,
            messages=messages,
        )
        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason != "tool_use":
            return _first_text(response.content)

        tool_results = [
            {
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": json.dumps(
                    _execute_tool(block.name, block.input, incidents, conn)
                ),
            }
            for block in response.content
            if getattr(block, "type", None) == "tool_use"
        ]
        if not tool_results:
            break
        messages.append({"role": "user", "content": tool_results})

    # Rounds exhausted — ensure messages ends with a user turn before the
    # final synthesis call (Anthropic API requires alternating roles).
    if messages[-1]["role"] == "assistant":
        messages.append({
            "role": "user",
            "content": "Write your final investigation report based on what you found.",
        })
    final = client.messages.create(
        model=MODEL,
        max_tokens=1024,
        system=system_prompt,
        messages=messages,
    )
    return _first_text(final.content)
