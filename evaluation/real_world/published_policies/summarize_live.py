"""Aggregates live/summary.jsonl into a confusion count, written to live/summary.json."""
import json
from collections import Counter

rows = [json.loads(l) for l in open("evaluation/real_world/published_policies/live/summary.jsonl")]
c = Counter(r["outcome"] for r in rows)
out = {"n_cases": len(rows), "outcomes": dict(c)}
json.dump(out, open("evaluation/real_world/published_policies/live/summary.json", "w"), indent=1)
print(json.dumps(out, indent=1))
