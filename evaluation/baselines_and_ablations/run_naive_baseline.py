"""
evaluation/baselines_and_ablations/run_naive_baseline.py

Runs the naive baseline (naive_baseline.py) against the SAME case sets
already used to evaluate CrossGuard: the generated benchmark (section 10 of
POLICY_SEMANTICS_EVALUATION.md; dev/heldout .jsonl, generated fresh here
rather than requiring the large files on disk) and the real-world published
policies (section 11; RWP-*). Reports a confusion matrix per case set and
per category, for direct comparison against CrossGuard's own results
(evaluation/generated_benchmark/*_results_reference.json and
evaluation/real_world/published_policies/offline_results.json).

    python -m evaluation.baselines_and_ablations.run_naive_baseline
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict

from evaluation.baselines_and_ablations.naive_baseline import naive_flags
from evaluation.generated_benchmark.generator import generate
from evaluation.real_world.published_policies.build_cases import all_cases as rwp_cases


def score(declared, found):
    if declared is None:
        return "unresolved(naive can't distinguish)" if found else "unresolved(naive says no)"
    if declared:
        return "TP" if found else "FN"
    return "FP" if found else "TN"


def run_generated(n, seed, split):
    cases = generate(n, seed, split)
    outcomes = Counter()
    by_category = defaultdict(Counter)
    by_recipe = defaultdict(Counter)
    for c in cases:
        raw = json.loads(json.dumps({
            "entry_sa": c.entry_sa, "roles": c.roles, "sa_role_map": c.sa_role_map,
        }))
        found = naive_flags(raw)
        outc = score(c.truth["reachable"], found)
        outcomes[outc] += 1
        by_category[c.category][outc] += 1
        by_recipe[c.recipe][outc] += 1
    return {"split": split, "n": n, "outcomes": dict(outcomes),
           "by_category": {k: dict(v) for k, v in by_category.items()},
           "by_recipe": {k: dict(v) for k, v in by_recipe.items()}}


def run_rwp():
    outcomes = Counter()
    rows = []
    for case_id, case in rwp_cases().items():
        found = naive_flags(case)
        outc = score(case["truth"]["reachable"], found)
        outcomes[outc] += 1
        rows.append({"case_id": case_id, "declared": case["truth"]["reachable"], "found": found, "outcome": outc})
    return {"outcomes": dict(outcomes), "rows": rows}


def summarize(outcomes):
    tp, fp, fn, tn = outcomes.get("TP", 0), outcomes.get("FP", 0), outcomes.get("FN", 0), outcomes.get("TN", 0)
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    return {"precision": round(precision, 4) if precision is not None else None,
           "recall": round(recall, 4) if recall is not None else None}


def main():
    dev = run_generated(4000, 30001, "dev")
    heldout = run_generated(4000, 77777, "heldout")
    rwp = run_rwp()
    out = {
        "dev": {**dev, "summary": summarize(dev["outcomes"])},
        "heldout": {**heldout, "summary": summarize(heldout["outcomes"])},
        "rwp": {**rwp, "summary": summarize(rwp["outcomes"])},
    }
    print(json.dumps({k: v["summary"] for k, v in out.items()}, indent=1))
    print(json.dumps({k: v["outcomes"] for k, v in out.items()}, indent=1))
    with open("evaluation/baselines_and_ablations/naive_baseline_results.json", "w") as f:
        json.dump(out, f, indent=1)
    return out


if __name__ == "__main__":
    main()
