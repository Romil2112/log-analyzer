"""
Compile detections into native SIEM queries with pySigma backends.

Where ``sigma_export`` emits vendor-neutral Sigma YAML (for the ``sigma`` CLI),
this module goes one step further and produces ready-to-run queries for three
SIEMs using real pySigma backends and per-SIEM field-mapping pipelines:

    * Splunk            -> SPL          (CIM field schema)
    * Elastic           -> ES|QL        (ECS field schema)
    * Microsoft Sentinel-> KQL          (ASIM field schema)

The detections are inherently threshold-based (N failed logins, N distinct
ports, N 404s in a window), so each is expressed as a Sigma *correlation* rule
(``event_count`` / ``value_count``). The Splunk and ES|QL backends compile the
correlation directly into a native ``stats``/``summarize`` aggregation. The
Kusto (Sentinel) backend does not yet emit correlations, so we compile the base
detection with pySigma and append the equivalent KQL ``summarize … | where``
aggregation natively — the field mapping still comes from the pySigma pipeline.
"""
from __future__ import annotations

import uuid
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation

from sigma.backends.splunk import SplunkBackend
from sigma.backends.elasticsearch.elasticsearch_esql import ESQLBackend
from sigma.backends.kusto import KustoBackend

import sigma_export

# Stable UUID namespace so generated rule ids are deterministic across runs.
_NS = uuid.UUID("1b4d3c2e-0000-4000-8000-abcdef012345")

# Per-incident detection spec used to build the Sigma correlation rule.
#   selection : base-rule field match (neutral field names)
#   logsource : Sigma logsource category
#   ctype     : "event_count" (count rows) or "value_count" (count distinct field)
#   group_by  : correlation grouping field (neutral name)
#   field     : counted field for value_count (neutral name)
#   gte       : threshold; timespan: correlation window
_SPECS: dict[str, dict] = {
    "brute_force": {
        "selection": {"event_type": "failed_login"},
        "logsource": {"category": "authentication"},
        "ctype": "event_count", "group_by": "source_ip",
        "gte": 5, "timespan": "10m",
    },
    "port_scan": {
        "selection": {"event_type": "connection"},
        "logsource": {"category": "network_connection"},
        "ctype": "value_count", "group_by": "source_ip", "field": "port",
        "gte": 20, "timespan": "5m",
    },
    "flood_404": {
        "selection": {"event_type": "http_404"},
        "logsource": {"category": "webserver"},
        "ctype": "event_count", "group_by": "source_ip",
        "gte": 30, "timespan": "5m",
    },
}

# Per-SIEM target: backend, file extension, label, native field schema, and the
# KQL summarize aggregator used when we hand-build the Sentinel aggregation.
_TARGETS: dict[str, dict] = {
    "splunk": {
        "label": "Splunk SPL", "ext": "spl", "backend": SplunkBackend,
        "fields": {"source_ip": "src_ip", "port": "dest_port"},
    },
    "esql": {
        "label": "Elastic ES|QL", "ext": "esql", "backend": ESQLBackend,
        "fields": {"source_ip": "source.ip", "port": "destination.port"},
    },
    "sentinel": {
        "label": "Microsoft Sentinel KQL", "ext": "kql", "backend": KustoBackend,
        "fields": {"source_ip": "SrcIpAddr", "port": "DstPortNumber"},
        "kql_count": {"event_count": "count()", "value_count": "dcount({field})"},
    },
}

# Backends that can compile a Sigma correlation rule into a native aggregation.
_CORRELATION_CAPABLE = {"splunk", "esql"}

SUPPORTED_TARGETS = tuple(_TARGETS)


def _pipeline(field_map: dict[str, str]) -> ProcessingPipeline:
    """A pySigma pipeline that renames neutral fields to a SIEM's schema."""
    return ProcessingPipeline(
        items=[ProcessingItem(transformation=FieldMappingTransformation(field_map))]
    )


def _rule_uuid(incident_type: str, suffix: str) -> str:
    return str(uuid.uuid5(_NS, f"{incident_type}:{suffix}"))


def _base_rule_yaml(incident_type: str, spec: dict, meta: dict, name: str) -> str:
    """Standard, pySigma-parseable base detection rule (no aggregation)."""
    selection = "\n".join(f"        {k}: {v}" for k, v in spec["selection"].items())
    logsource = "\n".join(f"    {k}: {v}" for k, v in spec["logsource"].items())
    tags = "\n".join(f"    - {t}" for t in meta["tags"])
    return (
        f"title: {meta['title']}\n"
        f"name: {name}\n"
        f"id: {_rule_uuid(incident_type, 'base')}\n"
        f"status: experimental\n"
        f"description: {meta['description']}\n"
        f"logsource:\n{logsource}\n"
        f"detection:\n"
        f"    selection:\n{selection}\n"
        f"    condition: selection\n"
        f"level: {meta['level']}\n"
        f"tags:\n{tags}\n"
    )


def _correlation_yaml(incident_type: str, spec: dict, base_name: str) -> str:
    """The Sigma correlation rule (event_count / value_count) over the base."""
    cond = f"        gte: {spec['gte']}"
    if spec["ctype"] == "value_count":
        cond += f"\n        field: {spec['field']}"
    return (
        f"title: {incident_type} threshold\n"
        f"id: {_rule_uuid(incident_type, 'corr')}\n"
        f"status: experimental\n"
        f"correlation:\n"
        f"    type: {spec['ctype']}\n"
        f"    rules:\n        - {base_name}\n"
        f"    group-by:\n        - {spec['group_by']}\n"
        f"    timespan: {spec['timespan']}\n"
        f"    condition:\n{cond}\n"
    )


def _sentinel_aggregation(spec: dict, fields: dict, count_tpl: dict) -> str:
    """Build the KQL `summarize … | where` tail for the Kusto backend.

    The base `where` predicate comes from pySigma; this appends the threshold
    aggregation natively because the Kusto backend can't emit correlations yet.
    """
    group_field = fields.get(spec["group_by"], spec["group_by"])
    if spec["ctype"] == "value_count":
        counted = fields.get(spec["field"], spec["field"])
        agg = count_tpl["value_count"].format(field=counted)
        alias = "value_count"
    else:
        agg = count_tpl["event_count"]
        alias = "event_count"
    window = spec["timespan"]
    return (
        f"\n| summarize {alias} = {agg} by bin(TimeGenerated, {window}), {group_field}"
        f"\n| where {alias} >= {spec['gte']}"
    )


def incident_to_queries(incident_type: str) -> dict[str, str] | None:
    """Compile one incident type into {target: native_query} for every SIEM.

    Returns None for unknown incident types.
    """
    spec = _SPECS.get(incident_type)
    meta = sigma_export.incident_to_sigma(incident_type)
    if spec is None or meta is None:
        return None

    base_name = f"{incident_type}_base"
    base_yaml = _base_rule_yaml(incident_type, spec, meta, base_name)
    corr_yaml = base_yaml + "---\n" + _correlation_yaml(incident_type, spec, base_name)

    queries: dict[str, str] = {}
    for target, cfg in _TARGETS.items():
        pipeline = _pipeline(cfg["fields"])
        backend = cfg["backend"](processing_pipeline=pipeline)
        if target in _CORRELATION_CAPABLE:
            out = backend.convert(SigmaCollection.from_yaml(corr_yaml))
            queries[target] = out[0]
        else:
            # Sentinel/Kusto: pySigma predicate + native KQL aggregation tail.
            out = backend.convert(SigmaCollection.from_yaml(base_yaml))
            queries[target] = out[0] + _sentinel_aggregation(
                spec, cfg["fields"], cfg["kql_count"]
            )
    return queries


def export_siem(incidents: list[dict], out_dir: str) -> list[str]:
    """Write native SIEM queries for each observed incident type.

    Produces one file per (incident type, SIEM) pair, e.g.
    ``brute_force.spl`` / ``brute_force.esql`` / ``brute_force.kql``.
    Returns the list of written file paths.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    seen, written = set(), []
    for inc in incidents:
        itype = inc.get("incident_type")
        if itype in seen:
            continue
        queries = incident_to_queries(itype)
        if queries is None:
            continue
        seen.add(itype)
        for target, query in queries.items():
            ext = _TARGETS[target]["ext"]
            label = _TARGETS[target]["label"]
            path = out / f"{itype}.{ext}"
            path.write_text(f"// {label} — generated by log-analyzer from Sigma\n{query}\n")
            written.append(str(path))
    return written


if __name__ == "__main__":  # pragma: no cover - manual smoke test
    import json
    for t in SUPPORTED_TARGETS:
        print(f"==== {t} ====")
    print(json.dumps(incident_to_queries("brute_force"), indent=2))
