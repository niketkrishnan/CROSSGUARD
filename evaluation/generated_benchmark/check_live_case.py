"""Called once per case by live_sample.sh. Compares one live main.py JSON
result against the case's declared truth and appends a row to
evaluation/generated_benchmark/live/summary.jsonl."""
import json
import sys

out_json, target, declared_str, case_id, entry_node = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
declared = {"True": True, "False": False, "None": None}[declared_str]
target = None if target == "None" else target

d = json.load(open(out_json))
# Every path is restricted to ones that ACTUALLY START at this case's own
# entry ServiceAccount -- with per-case LocalStack resets this is normally
# redundant, but it also protects the result if a case is re-run manually
# without a fresh reset.
paths = [p for p in d.get("paths", []) if p["path"][0] == entry_node]
hit = [p for p in paths if p["path"][-1] == target] if target else paths
found = bool(hit)
own_exposure_roles = [r for r in d.get("wildcard_trust_roles", []) if r.get("role") == target]
exposure = bool(own_exposure_roles) if target else len(d.get("wildcard_trust_roles", [])) > 0

if declared is None:
    ok = not any(p.get("confidence") == "confirmed" for p in hit)
    outcome = "handled_correctly" if ok else "WRONGLY_CONFIRMED"
elif declared:
    outcome = "TP" if (found or exposure) else "FN"
else:
    outcome = "FP" if found else "TN"

row = {"case_id": case_id, "target": target, "declared": declared, "outcome": outcome,
      "n_paths": len(hit), "confidence": hit[0]["confidence"] if hit else None}
with open("evaluation/generated_benchmark/live/summary.jsonl", "a") as f:
    f.write(json.dumps(row) + "\n")
print(f"  -> {outcome}")
