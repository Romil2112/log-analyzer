import os

# Prevent the OTel BatchSpanProcessor from trying to flush spans to a
# nonexistent Jaeger collector at the end of every local pytest run.
# Without this, each run logs StatusCode.UNAVAILABLE errors and exits slowly.
# CI is unaffected — CI also has no Jaeger, so this is a strict improvement.
os.environ.setdefault("OTEL_SDK_DISABLED", "true")
