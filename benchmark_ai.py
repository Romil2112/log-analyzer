"""Benchmark the concurrent AI summarization layer.

Runs the batch summarizer against a latency-simulating stub (no live API
calls, no cost) to measure the concurrency speedup and exercise the
token-cost / latency instrumentation. Use --help for options.

    python benchmark_ai.py --n 200 --latency 0.05 --concurrency 8
"""
import argparse
import time

from ai_scale import BatchMetrics, summarize_batch  # noqa: F401


class _Usage:
    def __init__(self, i, o):
        self.input_tokens, self.output_tokens = i, o


class _Block:
    def __init__(self, t):
        self.text = t


class _Msg:
    def __init__(self):
        self.content = [_Block("SOC summary: T1059 detected; isolate host and rotate creds.")]
        self.usage = _Usage(120, 60)


class LatencyStub:
    """Simulates a Claude call that takes `latency` seconds of I/O wait."""
    def __init__(self, latency):
        self.latency = latency
        self.messages = self

    def create(self, *, model, max_tokens, messages):
        time.sleep(self.latency)
        return _Msg()


def run(n, latency, concurrency):
    prompts = [f"incident batch {i}" for i in range(n)]
    serial_results, serial = summarize_batch(prompts, client=LatencyStub(latency), max_concurrency=1)
    conc_results, conc = summarize_batch(prompts, client=LatencyStub(latency), max_concurrency=concurrency)
    speedup = serial.wall_ms / conc.wall_ms if conc.wall_ms else 0.0
    print(f"=== AI summarization benchmark (stubbed {latency*1000:.0f}ms/call, n={n}) ===")
    print(f"serial (c=1):   {serial.wall_ms/1000:6.2f}s  {serial.throughput_per_s:6.2f}/s")
    print(f"concurrent (c={concurrency}): {conc.wall_ms/1000:6.2f}s  {conc.throughput_per_s:6.2f}/s")
    print(f"speedup:        {speedup:.1f}x")
    print(f"token cost (n={n}): ${conc.cost_usd:.4f}  (in={conc.input_tokens}, out={conc.output_tokens})")
    print(f"latency p50/p95: {conc.p50_ms:.1f} / {conc.p95_ms:.1f} ms")
    print(f"metrics: {conc.as_dict()}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--latency", type=float, default=0.05, help="simulated seconds per call")
    ap.add_argument("--concurrency", type=int, default=8)
    a = ap.parse_args()
    run(a.n, a.latency, a.concurrency)
