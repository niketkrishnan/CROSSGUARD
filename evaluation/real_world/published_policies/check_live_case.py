"""Called once per case by the script live_verify.py emits."""
import json
import sys

out_json, target, declared_str, case_id, entry_node = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
declared = {"True": True, "False": False}[declared_str]
target = None if target == "None" else target

d = json.load(open(out_json))
paths = [p for p in d.get("paths", []) if p["path"][0] == entry_node]
hit = [p for p in paths if p["path"][-1] == target] if target else paths
found = bool(hit)

if declared:
    outcome = "TP" if found else "FN"
else:
    outcome = "FP" if found else "TN"

row = {"case_id": case_id, "target": target, "declared": declared, "outcome": outcome,
      "n_paths": len(hit), "confidence": hit[0]["confidence"] if hit else None}
with open("evaluation/real_world/published_policies/live/summary.jsonl", "a") as f:
    f.write(json.dumps(row) + "\n")
print(f"  -> {outcome}")
