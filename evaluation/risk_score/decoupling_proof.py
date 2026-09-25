"""
evaluation/risk_score/decoupling_proof.py

The original paper's own limitation L-risk-scoring notes the weights in
scoring/risk.py (irsa_bridge=3.0, PassRole=2.5, AssumeRole=2.0,
rbac_binding=1.5, group_membership=1.0) are hand-designed heuristics, not
derived or externally validated, and its own Section IV-F sensitivity
analysis already concedes the score "is a useful heuristic, not a formally
invariant metric."

Code inspection (remediation/engine.py, _build_super_graph) shows the
min-cut remediation gives every REAL edge capacity=1 regardless of type --
risk_score is never read anywhere in remediation/engine.py. score_all_paths
(scoring/risk.py) only re-sorts the list of already-found paths for
DISPLAY order; it does not influence which edges pathfinder finds or which
edges the min-cut selects. If that is correct, remediation OUTPUT
(the set of cut edges, and therefore the tool's core correctness claim --
finding and closing every found path) is fully independent of the risk
score, so an unvalidated risk score is a much narrower claim on the paper
than "the tool's remediation depends on an unvalidated score" would be:
it would only affect the *order* findings are displayed to a user.

This module PROVES that empirically: it runs the SAME cases (drawn from
the already-validated fixtures in generated_benchmark and
baselines_and_ablations) through remediation with the production weights,
a flattened weighting, and a deliberately adversarial weighting (inverted
relative to production), and checks that the SET of cut edges is identical
across all three -- only risk_score values and path display order may
differ.

    python -m evaluation.risk_score.decoupling_proof
"""

from __future__ import annotations

import json
import logging

logging.disable(logging.WARNING)

from ingestion import policy_eval as pe  # noqa: E402
from pathfinder.search import annotate_path_confidence, find_all_cross_layer_paths  # noqa: E402
from remediation.engine import find_minimum_remediation  # noqa: E402
from scoring import risk as scoring_risk  # noqa: E402

from evaluation.baselines_and_ablations.mincut_vs_greedy import (  # noqa: E402
    build, shared_bottleneck_case, alternate_route_case, unreported_pair_case, disjoint_case,
)

WEIGHT_SETS = {
    "production": dict(scoring_risk.PERMISSION_WEIGHTS),
    "flattened": {"irsa_bridge": 2.0, "iam:PassRole": 1.8, "sts:AssumeRole": 1.5,
                 "rbac_binding": 1.2, "group_membership": 1.0},
    "adversarial_inverted": {"irsa_bridge": 1.0, "iam:PassRole": 1.5, "sts:AssumeRole": 3.0,
                             "rbac_binding": 2.5, "group_membership": 2.0},
}

CASE_BUILDERS = {
    "shared_bottleneck_4": lambda: shared_bottleneck_case(4),
    "alternate_route": alternate_route_case,
    "unreported_pair": unreported_pair_case,
    "disjoint": disjoint_case,
}


def edges_for_weights(G, paths, weights):
    """Re-score with a given weight set (does NOT touch pathfinder or the
    graph -- only the risk_score field and display order), then compute
    remediation, and return the SET of (source, target, edge_type) cut."""
    original = dict(scoring_risk.PERMISSION_WEIGHTS)
    scoring_risk.PERMISSION_WEIGHTS.clear()
    scoring_risk.PERMISSION_WEIGHTS.update(weights)
    try:
        scored = scoring_risk.score_all_paths(G, [dict(p) for p in paths])
        recs = find_minimum_remediation(G, scored)
    finally:
        scoring_risk.PERMISSION_WEIGHTS.clear()
        scoring_risk.PERMISSION_WEIGHTS.update(original)
    return {(r["source"], r["target"], r["edge_type"]) for r in recs}, [p["risk_score"] for p in scored]


def main():
    results = []
    for case_name, builder in CASE_BUILDERS.items():
        roles, maps, sas = builder()
        G, paths = build(roles, maps, sas)
        paths = annotate_path_confidence(G, paths)  # already includes confidence; harmless if re-applied
        per_weight = {}
        for wname, weights in WEIGHT_SETS.items():
            cut_set, scores = edges_for_weights(G, paths, weights)
            per_weight[wname] = {"cut_edges": sorted(f"{u.split(':')[-1].split('/')[-1]}->{v.split('/')[-1]}:{t}"
                                                     for u, v, t in cut_set),
                                 "risk_scores": scores}
        cut_sets = [frozenset(v["cut_edges"]) for v in per_weight.values()]
        identical = len(set(cut_sets)) == 1
        results.append({"case": case_name, "n_paths": len(paths),
                        "remediation_identical_across_all_weight_sets": identical,
                        "per_weight": per_weight})

    all_identical = all(r["remediation_identical_across_all_weight_sets"] for r in results)
    out = {"all_cases_remediation_invariant_to_risk_weights": all_identical, "cases": results}
    print(json.dumps(out, indent=1))
    with open("evaluation/risk_score/decoupling_results.json", "w") as f:
        json.dump(out, f, indent=1)
    return out


if __name__ == "__main__":
    main()
