"""
benchmarks/scale_test_2/run_scale_test.py

Runs the full pipeline against the Scale Test 2 fixture (10-hop deep
chain) 5 times, measuring wall-clock time and peak memory, confirming
BFS correctly finds the full-depth path on every run.
"""

import statistics
import sys
import time
import tracemalloc

sys.path.insert(0, ".")

from main import run

NUM_RUNS = 5

times = []
peak_memories_mb = []
hop_counts = []

for i in range(NUM_RUNS):
    print(f"\n=== Run {i + 1}/{NUM_RUNS} ===")
    tracemalloc.start()
    start = time.time()

    result = run(endpoint_url="http://localhost:4566")

    elapsed = time.time() - start
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    peak_mb = peak / 1024 / 1024
    hops = result["paths"][0]["hops"] if result["paths"] else None

    times.append(elapsed)
    peak_memories_mb.append(peak_mb)
    hop_counts.append(hops)

    print(f"Run {i + 1}: {elapsed:.2f}s | peak memory: {peak_mb:.1f}MB | hops: {hops}")

print("\n=== Summary over 5 runs ===")
print(f"Time:        mean={statistics.mean(times):.2f}s  stdev={statistics.stdev(times):.3f}s")
print(f"Peak memory: mean={statistics.mean(peak_memories_mb):.1f}MB  stdev={statistics.stdev(peak_memories_mb):.2f}MB")
print(f"Hops found:  {hop_counts}  (expected: [10, 10, 10, 10, 10])")
