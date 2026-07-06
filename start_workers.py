"""Launch the Conductor workers defined in conductor_workers.py.

Reads connection settings from the environment (set these before running):

    export CONDUCTOR_SERVER_URL="https://developer.orkescloud.com/api"
    export CONDUCTOR_AUTH_KEY="<your-key-id>"
    export CONDUCTOR_AUTH_SECRET="<your-key-secret>"

Optional, so the workers can actually do their job:
    export ANTHROPIC_API_KEY="<claude-key>"     # enables the summary stage
    export SOC_ALERTS_API_KEY="<soc-api-key>"   # if you prefer not to pass it per-run

Then:  python3 start_workers.py
The process polls Orkes for tasks until you Ctrl-C it. Trigger a workflow run from
the Orkes UI (or the API) and watch each stage execute.

NOTE ON THE RUNNER MODEL: the SDK's default TaskHandler spawns each worker in its own
OS process (multiprocessing). On macOS with Python 3.14 that subprocess model segfaults
(exitcode -11) on the first poll. We therefore run each worker in a *thread* in this one
process via TaskRunner, which is stable here. Same polling behavior, one process.
"""
from __future__ import annotations

import os
import sys
import threading

from conductor.client.automator.task_handler import get_registered_workers
from conductor.client.automator.task_runner import TaskRunner
from conductor.client.configuration.configuration import Configuration

# Importing this module registers the @worker_task functions with the SDK.
import conductor_workers  # noqa: F401


def main() -> None:
    if not os.environ.get("CONDUCTOR_SERVER_URL"):
        sys.exit(
            "CONDUCTOR_SERVER_URL is not set. Export CONDUCTOR_SERVER_URL / "
            "CONDUCTOR_AUTH_KEY / CONDUCTOR_AUTH_SECRET first (see this file's docstring)."
        )

    # Configuration() picks up CONDUCTOR_SERVER_URL / CONDUCTOR_AUTH_KEY /
    # CONDUCTOR_AUTH_SECRET from the environment automatically.
    config = Configuration()
    workers = get_registered_workers()
    names = [w.get_task_definition_name() for w in workers]
    print(f"Starting Conductor workers (thread-per-worker): {', '.join(names)}")
    print(f"Polling {config.host} -- Ctrl-C to stop.", flush=True)

    threads = []
    for worker in workers:
        runner = TaskRunner(worker=worker, configuration=config)
        t = threading.Thread(target=runner.run, name=worker.get_task_definition_name())
        t.daemon = True
        t.start()
        threads.append(t)

    try:
        # Keep the main thread alive while the daemon poll-threads work.
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\nStopping workers.")


if __name__ == "__main__":
    main()
