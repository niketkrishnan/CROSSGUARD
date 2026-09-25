"""
evaluation/generated_benchmark/run_benchmark.py

Runs CrossGuard (graph.builder + pathfinder, offline, no LocalStack) against
every case in a generated benchmark file, scores it against the oracle's
label (evaluation/generated_benchmark/oracle.py, independent of the code
under test), and writes a confusion matrix plus a per-recipe error taxonomy.

A case counts as a CrossGuard "hit" if it reports >=1 cross-layer path to
the case's declared target (or, for wildcard-trust cases, an exposure
finding is also accepted where the recipe expects one). Confidence tier is
compared against the recipe's declared tier for hard_positive cases.

    python -m evaluation.generated_benchmark.run_benchmark --split dev
    python -m evaluation.generated_benchmark.run_benchmark --split heldout
"""

from __future__ import annotations

import argparse
import logging

logging.disable(logging.WARNING)
import json
import types
from collections import Counter, defaultdict

from graph.builder import build_unified_graph
from ingestion import policy_eval as pe
from pathfinder.search import annotate_path_confidence, find_all_cross_layer_paths


def _sa(name, ns):
    o = types.SimpleNamespace()
    o.metadata = types.SimpleNamespace(name=name, namespace=ns, annotations=None)
    return o


def run_case(case: dict, cfg) -> dict:
    aws = {"users": [], "groups": [], "roles": case["roles"]}
    k8s = {"service_accounts": [_sa(case["entry_sa"], case["entry_ns"])],
          "roles": [], "role_bindings": [], "cluster_roles": [], "cluster_role_bindings": []}
    maps = [{"service_account": sa, "namespace": case["entry_ns"], "aws_role_arn": f"arn:aws:iam::000000000000:role/{rn}"}
           for sa, rn in case["sa_role_map"].items()]
    G = build_unified_graph(aws, k8s, maps, config=cfg)
    paths = annotate_path_confidence(G, find_all_cross_layer_paths(G))
    target = case["truth"].get("target")
    hit_paths = [p for p in paths if p["path"][-1] == target] if target else paths
    exposure = len(G.graph.get("wildcard_trust_roles", [])) > 0
    return {"paths": hit_paths, "all_paths": paths, "exposure": exposure,
           "suppressed": len(G.graph.get("suppressed_edges", []))}


def score(case: dict, result: dict) -> dict:
    truth = case["truth"]
    declared = truth["reachable"]
    found = bool(result["paths"]) or (truth.get("expect_exposure_finding") and result["exposure"] and declared)
    tier_found = result["paths"][0]["confidence"] if result["paths"] else None

    if case["category"] == "unresolved_by_design":
        # correct handling: either no confirmed/potential path (properly gated) and,
        # ideally, reported as unresolved somewhere (path or suppression)
        wrongly_confirmed = any(p["confidence"] == "confirmed" for p in result["paths"])
        properly_gated = not wrongly_confirmed
        return {"outcome": "handled_correctly" if properly_gated else "WRONGLY_CONFIRMED",
               "tier_found": tier_found, "n_paths": len(result["paths"])}

    if declared:
        expected_tier = truth.get("confidence")
        if not found:
            return {"outcome": "FN", "tier_found": None, "n_paths": 0}
        if tier_found == expected_tier or (result["exposure"] and truth.get("expect_exposure_finding")):
            return {"outcome": "TP", "tier_found": tier_found, "n_paths": len(result["paths"])}
        return {"outcome": "TP_WRONG_TIER", "tier_found": tier_found, "n_paths": len(result["paths"]),
               "expected_tier": expected_tier}
    else:
        if found:
            return {"outcome": "FP", "tier_found": tier_found, "n_paths": len(result["paths"])}
        return {"outcome": "TN", "tier_found": None, "n_paths": 0}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", choices=["dev", "heldout"], required=True)
    ap.add_argument("--semantics", choices=["strict", "annotate", "legacy"], default="strict")
    args = ap.parse_args()
    cfg = {"strict": pe.STRICT, "annotate": pe.ANNOTATE, "legacy": pe.LEGACY}[args.semantics]

    here = __file__.rsplit("/", 1)[0]
    path = f"{here}/{args.split}_cases.jsonl"
    outcomes = Counter()
    by_category = defaultdict(Counter)
    by_recipe = defaultdict(Counter)
    errors = []

    n = 0
    for line in open(path):
        case = json.loads(line)
        n += 1
        result = run_case(case, cfg)
        s = score(case, result)
        outcomes[s["outcome"]] += 1
        by_category[case["category"]][s["outcome"]] += 1
        by_recipe[case["recipe"]][s["outcome"]] += 1
        if s["outcome"] not in ("TP", "TN", "handled_correctly"):
            errors.append({"case_id": case["case_id"], "recipe": case["recipe"],
                           "category": case["category"], "truth": case["truth"], "score": s})

    TP, FP, FN, TN = outcomes["TP"], outcomes["FP"], outcomes["FN"], outcomes["TN"]
    wrong_tier = outcomes["TP_WRONG_TIER"]
    precision = TP / (TP + FP) if (TP + FP) else float("nan")
    recall = TP / (TP + FN + wrong_tier) if (TP + FN + wrong_tier) else float("nan")
    # wrong-tier counted against recall: right/wrong reachability alone is not the bar we claim

    out = {
        "split": args.split, "semantics": args.semantics, "n_cases": n,
        "confusion": {"TP": TP, "FP": FP, "FN": FN, "TN": TN, "TP_wrong_tier": wrong_tier,
                     "unresolved_handled_correctly": outcomes["handled_correctly"],
                     "unresolved_wrongly_confirmed": outcomes["WRONGLY_CONFIRMED"]},
        "precision": round(precision, 4) if precision == precision else None,
        "recall_strict_tier": round(recall, 4) if recall == recall else None,
        "by_category": {k: dict(v) for k, v in by_category.items()},
        "by_recipe": {k: dict(v) for k, v in by_recipe.items()},
        "n_errors": len(errors),
    }
    with open(f"{here}/{args.split}_results.json", "w") as f:
        json.dump(out, f, indent=1)
    with open(f"{here}/{args.split}_errors.jsonl", "w") as f:
        for e in errors:
            f.write(json.dumps(e) + "\n")
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
