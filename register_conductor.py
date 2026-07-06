"""Register the pipeline's task definitions + workflow on the Orkes server.

One-time (idempotent) setup so you don't have to hand-build anything in the UI.
Reads CONDUCTOR_SERVER_URL / CONDUCTOR_AUTH_KEY / CONDUCTOR_AUTH_SECRET from the
environment (same vars start_workers.py uses).

    python3 register_conductor.py

After this, the workflow "log_analyzer_soc_pipeline" exists on the server; start the
workers (start_workers.py) and trigger a run from the UI or API.
"""
from __future__ import annotations

import json
import os
import sys

from conductor.client.configuration.configuration import Configuration
from conductor.client.orkes.orkes_metadata_client import OrkesMetadataClient
from conductor.client.http.models.task_def import TaskDef
from conductor.client.http.models.workflow_def import WorkflowDef
from conductor.client.http.models.workflow_task import WorkflowTask
from conductor.client.http.models.sub_workflow_params import SubWorkflowParams

HERE = os.path.dirname(os.path.abspath(__file__))
# Register both the core pipeline and the multi-source fan-out parent (each its own file).
WORKFLOW_JSONS = [
    os.path.join(HERE, "conductor_workflow.json"),
    os.path.join(HERE, "conductor_multi_source.json"),
]

OWNER_EMAIL = "shahromil71321@gmail.com"

# Task defs: parsing/analysis can be slow on big logs, so give those generous timeouts.
# analyze_log backs the v1 straight-line workflow; the detect_*/ml_score/join_incidents
# tasks back the v2 fork/join workflow. Both versions coexist on the server.
TASK_DEFS = [
    {"name": "analyze_log", "response_timeout_seconds": 600, "timeout_seconds": 900},
    {"name": "detect_brute_force", "response_timeout_seconds": 600, "timeout_seconds": 900},
    {"name": "detect_port_scan", "response_timeout_seconds": 600, "timeout_seconds": 900},
    {"name": "detect_404_flood", "response_timeout_seconds": 600, "timeout_seconds": 900},
    {"name": "ml_score", "response_timeout_seconds": 600, "timeout_seconds": 900},
    {"name": "join_incidents", "response_timeout_seconds": 120, "timeout_seconds": 180},
    # enrich_geoip does LOCAL threat-intel + MaxMind GeoIP lookups (no network); ms-scale
    # for a handful of incidents. 60/120 matches the I/O-bound tier (like push_to_dashboard)
    # with wide margin for a cold DB open, rather than reusing join_incidents' heavier 120/180.
    {"name": "enrich_geoip", "response_timeout_seconds": 60, "timeout_seconds": 120},
    {"name": "generate_claude_summary", "response_timeout_seconds": 120, "timeout_seconds": 180},
    {"name": "push_to_dashboard", "response_timeout_seconds": 60, "timeout_seconds": 120},
]


def _workflow_task(t: dict) -> WorkflowTask:
    """Build a WorkflowTask from the JSON spec, handling FORK_JOIN/JOIN structure.

    FORK_JOIN tasks carry ``forkTasks`` (a list of parallel branches, each a list of
    tasks) and JOIN tasks carry ``joinOn`` (the branch reference names to wait on). The
    SDK's WorkflowTask constructor signature varies across versions, so set those two
    fields as attributes after construction rather than as kwargs."""
    wt = WorkflowTask(
        name=t["name"],
        task_reference_name=t["taskReferenceName"],
        type=t["type"],
        input_parameters=t.get("inputParameters", {}),
    )
    if t.get("forkTasks"):
        wt.fork_tasks = [[_workflow_task(x) for x in branch] for branch in t["forkTasks"]]
    if t.get("joinOn"):
        wt.join_on = t["joinOn"]
    if t.get("subWorkflowParam"):
        swp = t["subWorkflowParam"]
        wt.sub_workflow_param = SubWorkflowParams(name=swp["name"], version=swp.get("version"))
    return wt


def _workflow_def_from_json(path: str) -> WorkflowDef:
    with open(path) as fh:
        spec = json.load(fh)
    tasks = [_workflow_task(t) for t in spec["tasks"]]
    return WorkflowDef(
        name=spec["name"],
        description=spec.get("description"),
        version=spec.get("version", 1),
        schema_version=spec.get("schemaVersion", 2),
        owner_email=spec.get("ownerEmail", OWNER_EMAIL),
        timeout_seconds=spec.get("timeoutSeconds", 0),
        input_parameters=spec.get("inputParameters", []),
        output_parameters=spec.get("outputParameters", {}),
        tasks=tasks,
    )


def main() -> None:
    if not os.environ.get("CONDUCTOR_SERVER_URL"):
        sys.exit("CONDUCTOR_SERVER_URL not set -- export your Orkes env vars first.")

    metadata = OrkesMetadataClient(Configuration())

    # Authenticated call -- fails loudly here if the key/secret are wrong.
    existing = {t.name for t in metadata.get_all_task_defs()}
    print(f"Connected to Orkes. {len(existing)} task defs already registered.")

    for td in TASK_DEFS:
        metadata.register_task_def(
            TaskDef(
                name=td["name"],
                owner_email=OWNER_EMAIL,
                retry_count=2,
                retry_logic="FIXED",
                retry_delay_seconds=5,
                timeout_seconds=td["timeout_seconds"],
                response_timeout_seconds=td["response_timeout_seconds"],
                timeout_policy="TIME_OUT_WF",
            )
        )
        print(f"  registered task def: {td['name']}")

    for path in WORKFLOW_JSONS:
        wf = _workflow_def_from_json(path)
        metadata.register_workflow_def(wf, overwrite=True)
        print(f"registered workflow: {wf.name} (v{wf.version})")
    print("\nDone. Start workers with:  python3 start_workers.py")


if __name__ == "__main__":
    main()
