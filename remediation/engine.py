"""
remediation/engine.py

Computes the minimum set of graph edges whose removal breaks ALL found
escalation paths simultaneously (C4) -- a global minimum edge cut
problem -- and translates each cut edge into a human-readable,
type-aware fix recommendation with an actual command to run.

Implementation note: we don't compute a separate minimum cut per path
and union/dedupe the results. When multiple paths share a common
bottleneck edge, computing cuts independently can miss that shared
bottleneck entirely (NetworkX may return a different, locally-minimal
but globally-redundant cut for each path). Instead we solve ONE global
min-cut problem using a super-source connected to every path's start
node and a super-sink connected from every path's end node, with
"infinite" capacity on those virtual edges and capacity=1 on every real
edge -- this guarantees the smallest possible set of REAL edges that
disconnects every entry point from every admin node at once.

Theoretical foundation: "Scalable Edge Blocking for Attack Graphs"
(AAAI 2023). Simpler than MaxSAT+GNN approaches (e.g. IAMPERE) while
still being provably minimal.
"""

from __future__ import annotations

import logging

import networkx as nx

logger = logging.getLogger(__name__)

_SUPER_SOURCE = "__super_source__"
_SUPER_SINK = "__super_sink__"


def _format_irsa_bridge(src: str, dst: str, G: nx.DiGraph) -> dict:
    src_data = G.nodes[src]
    sa_name = src_data.get("name", src)
    namespace = src_data.get("namespace", "default")
    return {
        "action": f"Remove IRSA annotation from ServiceAccount {namespace}/{sa_name}",
        "edge_type": "irsa_bridge",
        "command": (
            f"kubectl annotate serviceaccount {sa_name} -n {namespace} "
            f"eks.amazonaws.com/role-arn-"
        ),
    }


def _format_assume_role(src: str, dst: str, G: nx.DiGraph) -> dict:
    src_data = G.nodes[src]
    dst_data = G.nodes[dst]
    src_name = src_data.get("name", src)
    dst_name = dst_data.get("name", dst)
    return {
        "action": f"Remove {src_name} from the trust policy of role {dst_name}",
        "edge_type": "sts:AssumeRole",
        "command": (
            f"aws iam update-assume-role-policy --role-name {dst_name} "
            f"--policy-document file://updated-trust-policy.json   "
            f"# (remove the statement allowing {src_name} to assume this role)"
        ),
    }


def _format_pass_role(src: str, dst: str, G: nx.DiGraph) -> dict:
    src_data = G.nodes[src]
    dst_data = G.nodes[dst]
    src_name = src_data.get("name", src)
    dst_name = dst_data.get("name", dst)
    return {
        "action": f"Remove iam:PassRole permission for {dst_name} from {src_name}'s policy",
        "edge_type": "iam:PassRole",
        "command": (
            f"# Edit the inline/attached policy on {src_name}: remove the "
            f"iam:PassRole statement whose Resource includes {dst_name} "
            f"(or replace a wildcard Resource with the specific roles actually needed)"
        ),
    }


def _format_rbac_binding(src: str, dst: str, G: nx.DiGraph) -> dict:
    src_data = G.nodes[src]
    dst_data = G.nodes[dst]
    sa_name = src_data.get("name", src)
    namespace = src_data.get("namespace", "default")
    role_name = dst_data.get("name", dst)
    return {
        "action": f"Remove the RoleBinding granting {namespace}/{sa_name} access to {role_name}",
        "edge_type": "rbac_binding",
        "command": (
            f"kubectl get rolebindings,clusterrolebindings -A "
            f"-o json | jq '.items[] | select(.subjects[]?.name==\"{sa_name}\")'   "
            f"# find and delete the relevant binding"
        ),
    }


def _format_group_membership(src: str, dst: str, G: nx.DiGraph) -> dict:
    src_data = G.nodes[src]
    dst_data = G.nodes[dst]
    user_name = src_data.get("name", src)
    group_name = dst_data.get("name", dst)
    return {
        "action": f"Remove user {user_name} from group {group_name}",
        "edge_type": "group_membership",
        "command": f"aws iam remove-user-from-group --user-name {user_name} --group-name {group_name}",
    }


def _format_generic(src: str, dst: str, edge_type: str) -> dict:
    return {
        "action": f"Remove edge of type '{edge_type}' from {src} to {dst}",
        "edge_type": edge_type,
        "command": "",
    }


_FORMATTERS = {
    "irsa_bridge": _format_irsa_bridge,
    "sts:AssumeRole": _format_assume_role,
    "iam:PassRole": _format_pass_role,
    "rbac_binding": _format_rbac_binding,
    "group_membership": _format_group_membership,
}


def format_remediation(src: str, dst: str, edge_type: str, G: nx.DiGraph) -> dict:
    """Translate a single (src, dst) edge into a human-readable, type-aware
    fix recommendation. Falls back to a generic description for edge types
    we haven't written a specific formatter for yet."""
    formatter = _FORMATTERS.get(edge_type)
    if formatter is None:
        return _format_generic(src, dst, edge_type)
    return formatter(src, dst, G)


def _build_super_graph(G: nx.DiGraph, starts: set[str], ends: set[str]) -> tuple[nx.DiGraph, float]:
    """Build an augmented graph with a super-source connected to every
    entry point and a super-sink connected from every admin node, so we
    can solve ONE global min-cut instead of per-path cuts that can miss
    shared bottlenecks."""
    H = nx.DiGraph()
    H.add_nodes_from(G.nodes(data=True))
    for u, v, data in G.edges(data=True):
        H.add_edge(u, v, capacity=1, **data)

    # "Infinite" capacity: bigger than any possible real cut, so the
    # algorithm will never choose to cut a virtual edge instead of a real one.
    infinite_capacity = G.number_of_edges() + 1

    H.add_node(_SUPER_SOURCE)
    H.add_node(_SUPER_SINK)
    for s in starts:
        if G.has_node(s):
            H.add_edge(_SUPER_SOURCE, s, capacity=infinite_capacity, type="virtual")
    for e in ends:
        if G.has_node(e):
            H.add_edge(e, _SUPER_SINK, capacity=infinite_capacity, type="virtual")

    return H, infinite_capacity


def find_minimum_remediation(G: nx.DiGraph, paths: list[dict]) -> list[dict]:
    """Compute the single smallest set of real edges whose removal breaks
    EVERY given escalation path at once, and translate each into a
    remediation recommendation.

    Args:
        G: the unified graph.
        paths: list of path dicts as returned by pathfinder.search
            (must have "start" and "end" keys).

    Returns:
        Deduplicated list of remediation recommendation dicts, each with
        "action" (human-readable), "edge_type", and "command".
    """
    if not paths:
        return []

    starts = {p["start"] for p in paths}
    ends = {p["end"] for p in paths}

    H, _ = _build_super_graph(G, starts, ends)

    try:
        _, (reachable, non_reachable) = nx.minimum_cut(
            H, _SUPER_SOURCE, _SUPER_SINK, capacity="capacity"
        )
    except nx.NetworkXError:
        logger.warning("Could not compute global minimum cut for remediation")
        return []

    cut_edges = []
    for u in reachable:
        for v in H[u]:
            if v in non_reachable and H.edges[u, v].get("type") != "virtual":
                cut_edges.append((u, v))

    recommendations = []
    for src, dst in cut_edges:
        edge_data = G.edges[src, dst]
        edge_type = edge_data.get("type", "unknown")
        recommendations.append(format_remediation(src, dst, edge_type, G))

    # Deduplicate by the human-readable action string (shouldn't be needed
    # now that we compute one global cut, but cheap safety net).
    unique = list({r["action"]: r for r in recommendations}.values())
    return unique
