"""Production-scale concurrent Claude summarization.

Wraps the single-call path in `ai_summary` with the concerns that matter when
LLM calls run at volume: bounded concurrency, retry-with-backoff on rate limits
and transient errors, and per-run token-cost + latency instrumentation.

The Anthropic client is dependency-injected, so every code path here is unit
-testable with a stub — no API key or network required. In production, build the
real client with `build_client()`.
"""
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

MODEL = "claude-haiku-4-5-20251001"
# USD per 1M tokens (Claude Haiku 4.5). Update alongside MODEL.
PRICE_PER_MTOK = {"input": 1.00, "output": 5.00}

# Exception class names / HTTP statuses that are safe to retry.
_RETRYABLE_NAMES = {
    "RateLimitError", "APITimeoutError", "APIConnectionError",
    "InternalServerError", "OverloadedError",
}
_RETRYABLE_STATUS = {429, 500, 502, 503, 529}


__all__ = [
    "estimate_cost", "BatchMetrics", "build_incident_prompt",
    "looks_valid", "summarize_batch", "build_client",
]


def estimate_cost(input_tokens, output_tokens, price=PRICE_PER_MTOK):
    """USD cost for a token count at the given per-1M-token pricing."""
    return (input_tokens / 1_000_000) * price["input"] + \
           (output_tokens / 1_000_000) * price["output"]


def _is_retryable(exc):
    if type(exc).__name__ in _RETRYABLE_NAMES:
        return True
    return getattr(exc, "status_code", None) in _RETRYABLE_STATUS


@dataclass
class BatchMetrics:
    """Aggregate instrumentation for one batch run."""
    total: int = 0
    succeeded: int = 0
    failed: int = 0
    retries: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    latencies_ms: list = field(default_factory=list)
    wall_ms: float = 0.0

    @property
    def cost_usd(self):
        return estimate_cost(self.input_tokens, self.output_tokens)

    @property
    def p50_ms(self):
        return statistics.median(self.latencies_ms) if self.latencies_ms else 0.0

    @property
    def p95_ms(self):
        if not self.latencies_ms:
            return 0.0
        s = sorted(self.latencies_ms)
        return s[min(len(s) - 1, int(round(0.95 * (len(s) - 1))))]

    @property
    def throughput_per_s(self):
        return (self.succeeded / (self.wall_ms / 1000)) if self.wall_ms else 0.0

    def as_dict(self):
        return {
            "total": self.total, "succeeded": self.succeeded, "failed": self.failed,
            "retries": self.retries, "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens, "cost_usd": round(self.cost_usd, 6),
            "p50_ms": round(self.p50_ms, 1), "p95_ms": round(self.p95_ms, 1),
            "throughput_per_s": round(self.throughput_per_s, 2),
            "wall_ms": round(self.wall_ms, 1),
        }


def build_incident_prompt(incidents):
    """Build the SOC-summary prompt for one group of incidents."""
    inc_text = "\n".join(
        f"- {i['incident_type']} from {i['source_ip']}, "
        f"count={i['event_count']}, MITRE={i.get('mitre', {}).get('id', '?')}"
        for i in incidents
    )
    return ("You are a SOC analyst. Write a 3-sentence executive summary of these "
            f"security incidents:\n{inc_text}\nInclude MITRE technique IDs and "
            "remediation advice.")


def looks_valid(text):
    """Lightweight eval gate: a usable summary is non-empty prose."""
    return bool(text) and len(text.strip()) >= 20


def _parse_ai_response(msg, latency_ms, retries):
    """Extract text + token usage from a successful API response into a result dict."""
    usage = getattr(msg, "usage", None)
    it = int(getattr(usage, "input_tokens", 0) or 0)
    ot = int(getattr(usage, "output_tokens", 0) or 0)
    text = msg.content[0].text if getattr(msg, "content", None) else ""
    return dict(ok=True, text=text, latency_ms=latency_ms,
                input_tokens=it, output_tokens=ot, retries=retries, error=None)


def _summarize_one(client, prompt, *, model, max_tokens, max_retries, backoff_base, sleep):
    retries = 0
    while True:
        try:
            t0 = time.perf_counter()
            msg = client.messages.create(
                model=model, max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )
            dt = (time.perf_counter() - t0) * 1000
            return _parse_ai_response(msg, dt, retries)
        except Exception as exc:  # noqa: BLE001 - classified by _is_retryable
            if retries >= max_retries or not _is_retryable(exc):
                return dict(ok=False, text=None, latency_ms=0.0, input_tokens=0,
                            output_tokens=0, retries=retries, error=str(exc))
            sleep(backoff_base * (2 ** retries))
            retries += 1


def summarize_batch(prompts, *, client, model=MODEL, max_tokens=200,
                    max_concurrency=8, max_retries=3, backoff_base=0.5, sleep=time.sleep):
    """Summarize many prompts concurrently. Returns (results, BatchMetrics).

    `results[i]` is the summary text for `prompts[i]`, or None if that call
    failed after exhausting retries. Order is preserved.
    """
    metrics = BatchMetrics(total=len(prompts))
    results = [None] * len(prompts)
    if not prompts:
        return results, metrics
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=max(1, max_concurrency)) as ex:
        futs = {
            ex.submit(_summarize_one, client, p, model=model, max_tokens=max_tokens,
                      max_retries=max_retries, backoff_base=backoff_base, sleep=sleep): i
            for i, p in enumerate(prompts)
        }
        for fut in as_completed(futs):
            i = futs[fut]
            r = fut.result()
            results[i] = r["text"]
            metrics.retries += r["retries"]
            if r["ok"]:
                metrics.succeeded += 1
                metrics.input_tokens += r["input_tokens"]
                metrics.output_tokens += r["output_tokens"]
                metrics.latencies_ms.append(r["latency_ms"])
            else:
                metrics.failed += 1
    metrics.wall_ms = (time.perf_counter() - t0) * 1000
    return results, metrics


def build_client(api_key=None):
    """Construct a real Anthropic client (lazy import to keep this module light)."""
    import os

    from anthropic import Anthropic
    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError("ANTHROPIC_API_KEY not set")
    return Anthropic(api_key=key)
