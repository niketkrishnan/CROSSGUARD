"""
scoring/risk.py

Assigns a numeric risk score to escalation paths found by
pathfinder.search, so multiple findings can be ranked ("fix this one
first"). Not a novel contribution on its own -- it's a practical layer
on top of C3 that makes the tool's output actionable.

score = (sum of edge weights / hop_count) * cross_layer_bonus
"""

from __future__ import annotations

import networkx as nx

# Higher weight = more directly dangerous / harder to "explain away" as
# intentional. irsa_bridge is weighted highest because it's the novel
# cross-layer edge this whole tool exists to find.
PERMISSION_WEIGHTS = {
    "irsa_bridge": 3.0,
    "iam:PassRole": 2.5,
    "sts:AssumeRole": 2.0,
    "rbac_binding": 1.5,
    "group_membership": 1.0,
}

DEFAULT_EDGE_WEIGHT = 1.0
CROSS_LAYER_BONUS = 2.0
SAME_LAYER_BONUS = 1.0


def score_path(G: nx.DiGraph, path_dict: dict) -> float:
    """Compute a risk score for a single path dict (as returned by
    pathfinder.search.find_escalation_paths / find_all_cross_layer_paths).

    Args:
        G: the unified graph the path was found in.
        path_dict: must have "path" (list of node ids) and "hops" (int),
            and may have "cross_layer" (bool, defaults to False if absent).

    Returns:
        A float risk score, rounded to 2 decimal places. Higher = riskier.
    """
    path = path_dict["path"]
    hop_count = path_dict["hops"]

    if hop_count == 0:
        # A 0-hop "path" is just a single node -- not a real escalation,
        # shouldn't happen in practice, but guard against div-by-zero.
        return 0.0

    edge_score = 0.0
    for i in range(len(path) - 1):
        edge_data = G.edges[path[i], path[i + 1]]
        edge_type = edge_data.get("type", "unknown")
        edge_score += PERMISSION_WEIGHTS.get(edge_type, DEFAULT_EDGE_WEIGHT)

    cross_layer_bonus = (
        CROSS_LAYER_BONUS if path_dict.get("cross_layer", False) else SAME_LAYER_BONUS
    )

    score = (edge_score / hop_count) * cross_layer_bonus
    return round(score, 2)


def score_all_paths(G: nx.DiGraph, paths: list[dict]) -> list[dict]:
    """Attach a 'risk_score' key to every path dict, and return the list
    re-sorted highest-risk-first (the order you'd want to present
    findings to a user, unlike pathfinder's shortest-first sort)."""
    for p in paths:
        p["risk_score"] = score_path(G, p)
    return sorted(paths, key=lambda p: p["risk_score"], reverse=True)
