"""
evaluation/real_world/published_policies/run_offline.py

Runs CrossGuard (graph.builder + pathfinder, in-memory, no LocalStack)
against the real-world cases in build_cases.py and checks each result
against its declared truth.

    python -m evaluation.real_world.published_policies.run_offline
"""

from __future__ import annotations

import json
import logging
import types

logging.disable(logging.WARNING)

from graph.builder import build_unified_graph  # noqa: E402
from ingestion import policy_eval as pe  # noqa: E402
from pathfinder.search import annotate_path_confidence, find_all_cross_layer_paths  # noqa: E402

from evaluation.real_world.published_policies.build_cases import all_cases  # noqa: E402


def _sa(name, ns):
    o = types.SimpleNamespace()
    o.metadata = types.SimpleNamespace(name=name, namespace=ns, annotations=None)
    return o


def run_case(case):
    aws = {"users": [], "groups": [], "roles": case["roles"]}
    k8s = {"service_accounts": [_sa(case["entry_sa"], case["entry_ns"])],
          "roles": [], "role_bindings": [], "cluster_roles": [], "cluster_role_bindings": []}
    maps = [{"service_account": sa, "namespace": case["entry_ns"], "aws_role_arn": rn}
           for sa, rn in [(sa, next(r["Arn"] for r in case["roles"] if r["RoleName"] == rn))
                          for sa, rn in case["sa_role_map"].items()]]
    G = build_unified_graph(aws, k8s, maps, config=pe.STRICT)
    paths = annotate_path_confidence(G, find_all_cross_layer_paths(G))
    return paths


def main():
    results = []
    for case_id, case in all_cases().items():
        paths = run_case(case)
        target = case["truth"].get("target")
        hit = [p for p in paths if p["path"][-1] == target] if target else paths
        found = bool(hit)
        declared = case["truth"]["reachable"]
        outcome = ("TP" if declared and found else "FN" if declared and not found
                  else "FP" if not declared and found else "TN")
        results.append({"case_id": case_id, "source": case["source"], "fully_verbatim": case["fully_verbatim"],
                        "declared": declared, "found": found,
                        "confidence": hit[0]["confidence"] if hit else None, "outcome": outcome})
    ok = all(r["outcome"] in ("TP", "TN") for r in results)
    print(json.dumps({"results": results, "all_correct": ok}, indent=1))
    with open("evaluation/real_world/published_policies/offline_results.json", "w") as f:
        json.dump({"results": results, "all_correct": ok}, f, indent=1)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
