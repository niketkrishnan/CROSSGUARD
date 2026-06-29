"""
benchmarks/scale_test_1/run_scale_test.py

Runs the full pipeline against the Scale Test 1 fixtures (50 users, 100
roles, 10 IRSA-annotated SAs, 2 with real escalation paths) 5 times,
measuring wall-clock time and peak memory each run, and reports mean +
standard deviation -- single-run numbers aren't statistically
meaningful for a paper.
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
path_counts = []

for i in range(NUM_RUNS):
    print(f"\n=== Run {i + 1}/{NUM_RUNS} ===")
    tracemalloc.start()
    start = time.time()

    result = run(endpoint_url="http://localhost:4566")

    elapsed = time.time() - start
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    peak_mb = peak / 1024 / 1024
    num_paths = len(result["paths"])

    times.append(elapsed)
    peak_memories_mb.append(peak_mb)
    path_counts.append(num_paths)

    print(f"Run {i + 1}: {elapsed:.2f}s | peak memory: {peak_mb:.1f}MB | paths found: {num_paths}")

print("\n=== Summary over 5 runs ===")
print(f"Time:        mean={statistics.mean(times):.2f}s  stdev={statistics.stdev(times):.3f}s")
print(f"Peak memory: mean={statistics.mean(peak_memories_mb):.1f}MB  stdev={statistics.stdev(peak_memories_mb):.2f}MB")
print(f"Paths found: {path_counts}  (expected: [2, 2, 2, 2, 2])")
