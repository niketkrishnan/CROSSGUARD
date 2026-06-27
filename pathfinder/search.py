"""
pathfinder/search.py

Searches the unified graph (graph.builder.build_unified_graph) for
privilege escalation paths -- specifically, paths that start in
Kubernetes RBAC and end at an AWS "admin" node. This is C3: cross-layer
path discovery, the thing no single-layer tool (PMapper, TAC, etc.) can
do, because they never see the Kubernetes side at all.
"""

from __future__ import annotations

import logging

import networkx as nx

logger = logging.getLogger(__name__)


def find_admin_nodes(G: nx.DiGraph) -> list[str]:
    """Return every node flagged is_admin=True -- these are the 'sinks'
    we're trying to reach (currently only AWS roles/users/groups can be
    flagged this way, since that's where is_admin is computed today)."""
    return [n for n, data in G.nodes(data=True) if data.get("is_admin", False)]


def find_k8s_entry_points(G: nx.DiGraph) -> list[str]:
    """Return every K8s node -- ServiceAccounts, Roles, ClusterRoles --
    as a possible attacker starting point (i.e. 'if you compromise a pod
    running as this identity, where can you go from here?')."""
    return [n for n, data in G.nodes(data=True) if str(data.get("type", "")).startswith("k8s")]


def is_cross_layer(G: nx.DiGraph, path: list[str]) -> bool:
    """A path is cross-layer if it touches at least one K8s node AND at
    least one AWS node -- i.e. it actually crosses the boundary that no
    single-layer tool can see across."""
    has_k8s = any(str(G.nodes[n].get("type", "")).startswith("k8s") for n in path)
    has_aws = any(str(G.nodes[n].get("type", "")).startswith("aws") for n in path)
    return has_k8s and has_aws


def find_escalation_paths(G: nx.DiGraph, start_node: str, admin_nodes: list[str]) -> list[dict]:
    """Find the shortest path from start_node to every admin node that's
    actually reachable. Unreachable admin nodes are silently skipped --
    that's normal, not an error (most entry points won't reach most
    admin nodes)."""
    paths = []
    for admin in admin_nodes:
        if admin == start_node:
            continue
        try:
            path = nx.shortest_path(G, source=start_node, target=admin)
        except nx.NetworkXNoPath:
            continue
        except nx.NodeNotFound:
            continue

        paths.append({
            "start": start_node,
            "end": admin,
            "path": path,
            "hops": len(path) - 1,
            "cross_layer": is_cross_layer(G, path),
        })
    return paths


def find_all_cross_layer_paths(G: nx.DiGraph) -> list[dict]:
    """The main entry point: find every escalation path that starts in
    Kubernetes and ends at an AWS admin node, sorted shortest-first
    (shorter paths are generally the most directly exploitable)."""
    k8s_nodes = find_k8s_entry_points(G)
    admin_nodes = find_admin_nodes(G)

    logger.info(
        "Searching for cross-layer paths: %d K8s entry points, %d admin nodes",
        len(k8s_nodes), len(admin_nodes),
    )

    all_paths: list[dict] = []
    for start in k8s_nodes:
        paths = find_escalation_paths(G, start, admin_nodes)
        cross_layer_paths = [p for p in paths if p["cross_layer"]]
        all_paths.extend(cross_layer_paths)

    all_paths.sort(key=lambda p: p["hops"])

    if all_paths:
        logger.warning("Found %d cross-layer escalation path(s)", len(all_paths))
    else:
        logger.info("No cross-layer escalation paths found")

    return all_paths


def describe_path(G: nx.DiGraph, path_dict: dict) -> str:
    """Human-readable rendering of a path, e.g.:
    k8s:sa:default:vulnerable-sa --[irsa_bridge]--> arn:...role/admin-role
    """
    path = path_dict["path"]
    parts = []
    for i, node in enumerate(path):
        node_data = G.nodes[node]
        label = node_data.get("name", node)
        parts.append(label)
        if i < len(path) - 1:
            edge_data = G.edges[path[i], path[i + 1]]
            parts.append(f"--[{edge_data.get('type', '?')}]-->")
    return " ".join(parts)
