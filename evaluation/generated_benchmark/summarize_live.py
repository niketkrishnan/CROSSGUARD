"""Aggregates evaluation/generated_benchmark/live/summary.jsonl into a confusion
matrix and writes live/summary.json, printed at the end of live_sample.sh."""
import json
from collections import Counter

rows = [json.loads(l) for l in open("evaluation/generated_benchmark/live/summary.jsonl")]
c = Counter(r["outcome"] for r in rows)
out = {"n_cases": len(rows), "outcomes": dict(c)}
json.dump(out, open("evaluation/generated_benchmark/live/summary.json", "w"), indent=1)
print(json.dumps(out, indent=1))
