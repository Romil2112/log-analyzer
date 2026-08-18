"""Quick launcher — runs the analyzer on the default test log and opens the report."""
import os
import subprocess
import sys
import webbrowser

ROOT = os.path.dirname(os.path.abspath(__file__))
VENV_PYTHON = os.path.join(ROOT, ".venv", "bin", "python3")
VENV_DIR = os.path.join(ROOT, ".venv")

# Re-launch under the venv interpreter if we're not already inside it.
if os.path.exists(VENV_PYTHON) and not sys.prefix.startswith(VENV_DIR):
    os.execv(VENV_PYTHON, [VENV_PYTHON] + sys.argv)

os.environ["OTEL_SDK_DISABLED"] = "true"

LOG = os.path.join(ROOT, "test_auth_10k.log")
REPORT = os.path.join(ROOT, "report.html")

subprocess.run(
    [sys.executable, "log_analyzer.py", LOG, "--no-db", "--report", REPORT],
    cwd=ROOT,
)

if os.path.exists(REPORT):
    webbrowser.open(f"file://{REPORT}")
