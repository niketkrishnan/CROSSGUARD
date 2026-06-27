"""Tests for pathfinder/search.py -- cross-layer escalation path discovery
(C3). Builds small synthetic NetworkX graphs directly (bypassing the
builder) so these tests are fast and isolated."""

import networkx as nx

from pathfinder.search import (
    describe_path,
    find_admin_nodes,
    find_all_cross_layer_paths,
    find_escalation_paths,
    find_k8s_entry_points,
    is_cross_layer,
)


def test_find_admin_nodes():
    G = nx.DiGraph()
    G.add_node("role-a", type="aws_role", is_admin=True)
    G.add_node("role-b", type="aws_role", is_admin=False)
    G.add_node("sa-1", type="k8s_service_account")  # no is_admin key at all

    assert find_admin_nodes(G) == ["role-a"]


def test_find_k8s_entry_points():
    G = nx.DiGraph()
    G.add_node("role-a", type="aws_role")
    G.add_node("sa-1", type="k8s_service_account")
    G.add_node("clusterrole-1", type="k8s_cluster_role")

    entry_points = find_k8s_entry_points(G)
    assert set(entry_points) == {"sa-1", "clusterrole-1"}


def test_is_cross_layer_true_when_both_present():
    G = nx.DiGraph()
    G.add_node("sa-1", type="k8s_service_account")
    G.add_node("role-a", type="aws_role")
    assert is_cross_layer(G, ["sa-1", "role-a"])


def test_is_cross_layer_false_when_only_k8s():
    G = nx.DiGraph()
    G.add_node("sa-1", type="k8s_service_account")
    G.add_node("clusterrole-1", type="k8s_cluster_role")
    assert not is_cross_layer(G, ["sa-1", "clusterrole-1"])


def test_simple_two_hop_irsa_path_found():
    # Mirrors Benchmark 1 exactly.
    G = nx.DiGraph()
    G.add_node("k8s:sa:default:vulnerable-sa", type="k8s_service_account")
    G.add_node("arn:role/admin-role", type="aws_role", is_admin=True)
    G.add_edge("k8s:sa:default:vulnerable-sa", "arn:role/admin-role", type="irsa_bridge")

    paths = find_escalation_paths(
        G, "k8s:sa:default:vulnerable-sa", find_admin_nodes(G)
    )
    assert len(paths) == 1
    assert paths[0]["hops"] == 1
    assert paths[0]["cross_layer"] is True
    assert paths[0]["path"] == ["k8s:sa:default:vulnerable-sa", "arn:role/admin-role"]


def test_no_path_when_disconnected():
    G = nx.DiGraph()
    G.add_node("sa-1", type="k8s_service_account")
    G.add_node("role-a", type="aws_role", is_admin=True)
    # no edge between them -- they're disconnected

    paths = find_escalation_paths(G, "sa-1", find_admin_nodes(G))
    assert paths == []


def test_multi_hop_chain_pod_sa_role_a_role_b_admin():
    # Mirrors Benchmark 2: SA -> Role A -> Role B (PassRole) -> Admin Role
    G = nx.DiGraph()
    G.add_node("k8s:sa:default:vulnerable-sa", type="k8s_service_account")
    G.add_node("arn:role/role-a", type="aws_role", is_admin=False)
    G.add_node("arn:role/role-b", type="aws_role", is_admin=False)
    G.add_node("arn:role/admin-role", type="aws_role", is_admin=True)

    G.add_edge("k8s:sa:default:vulnerable-sa", "arn:role/role-a", type="irsa_bridge")
    G.add_edge("arn:role/role-a", "arn:role/role-b", type="iam:PassRole")
    G.add_edge("arn:role/role-b", "arn:role/admin-role", type="sts:AssumeRole")

    paths = find_all_cross_layer_paths(G)
    assert len(paths) == 1
    assert paths[0]["hops"] == 3
    assert paths[0]["path"] == [
        "k8s:sa:default:vulnerable-sa",
        "arn:role/role-a",
        "arn:role/role-b",
        "arn:role/admin-role",
    ]


def test_no_cross_layer_paths_returns_empty_list_not_error():
    # Mirrors Benchmark 5 (control case): IRSA points to a low-priv role
    # with no path onward to admin.
    G = nx.DiGraph()
    G.add_node("k8s:sa:default:safe-sa", type="k8s_service_account")
    G.add_node("arn:role/low-priv-role", type="aws_role", is_admin=False)
    G.add_node("arn:role/admin-role", type="aws_role", is_admin=True)

    G.add_edge("k8s:sa:default:safe-sa", "arn:role/low-priv-role", type="irsa_bridge")
    # no edge from low-priv-role to admin-role -- dead end

    paths = find_all_cross_layer_paths(G)
    assert paths == []


def test_multiple_entry_points_only_vulnerable_one_has_path():
    # Mirrors Benchmark 3: 5 SAs, only 1 reaches admin.
    G = nx.DiGraph()
    G.add_node("arn:role/admin-role", type="aws_role", is_admin=True)
    for i in range(5):
        G.add_node(f"k8s:sa:default:sa-{i}", type="k8s_service_account")
    G.add_edge("k8s:sa:default:sa-2", "arn:role/admin-role", type="irsa_bridge")

    paths = find_all_cross_layer_paths(G)
    assert len(paths) == 1
    assert paths[0]["start"] == "k8s:sa:default:sa-2"


def test_paths_sorted_shortest_first():
    G = nx.DiGraph()
    G.add_node("arn:role/admin-role", type="aws_role", is_admin=True)
    G.add_node("k8s:sa:default:short-sa", type="k8s_service_account")
    G.add_node("k8s:sa:default:long-sa", type="k8s_service_account")
    G.add_node("arn:role/intermediate", type="aws_role")

    # short-sa: 1 hop to admin
    G.add_edge("k8s:sa:default:short-sa", "arn:role/admin-role", type="irsa_bridge")
    # long-sa: 2 hops to admin
    G.add_edge("k8s:sa:default:long-sa", "arn:role/intermediate", type="irsa_bridge")
    G.add_edge("arn:role/intermediate", "arn:role/admin-role", type="sts:AssumeRole")

    paths = find_all_cross_layer_paths(G)
    assert len(paths) == 2
    assert paths[0]["hops"] < paths[1]["hops"]
    assert paths[0]["start"] == "k8s:sa:default:short-sa"


def test_describe_path_human_readable():
    G = nx.DiGraph()
    G.add_node("k8s:sa:default:vulnerable-sa", type="k8s_service_account", name="vulnerable-sa")
    G.add_node("arn:role/admin-role", type="aws_role", name="admin-role", is_admin=True)
    G.add_edge("k8s:sa:default:vulnerable-sa", "arn:role/admin-role", type="irsa_bridge")

    path_dict = {
        "path": ["k8s:sa:default:vulnerable-sa", "arn:role/admin-role"],
        "hops": 1,
    }
    description = describe_path(G, path_dict)
    assert "vulnerable-sa" in description
    assert "admin-role" in description
    assert "irsa_bridge" in description
