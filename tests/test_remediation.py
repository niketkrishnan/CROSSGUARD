"""Tests for remediation/engine.py -- minimum-cut-based remediation (C4)."""

import networkx as nx

from remediation.engine import find_minimum_remediation, format_remediation


def test_format_remediation_irsa_bridge():
    G = nx.DiGraph()
    G.add_node(
        "k8s:sa:default:vulnerable-sa",
        type="k8s_service_account",
        name="vulnerable-sa",
        namespace="default",
    )
    G.add_node("arn:role/admin-role", type="aws_role", name="admin-role", is_admin=True)
    G.add_edge("k8s:sa:default:vulnerable-sa", "arn:role/admin-role", type="irsa_bridge")

    rec = format_remediation(
        "k8s:sa:default:vulnerable-sa", "arn:role/admin-role", "irsa_bridge", G
    )
    assert "vulnerable-sa" in rec["action"]
    assert "default" in rec["action"]
    assert "kubectl annotate" in rec["command"]
    assert "eks.amazonaws.com/role-arn-" in rec["command"]


def test_format_remediation_assume_role():
    G = nx.DiGraph()
    G.add_node("arn:role/caller", type="aws_role", name="caller-role")
    G.add_node("arn:role/target", type="aws_role", name="target-role", is_admin=True)
    G.add_edge("arn:role/caller", "arn:role/target", type="sts:AssumeRole")

    rec = format_remediation("arn:role/caller", "arn:role/target", "sts:AssumeRole", G)
    assert "caller-role" in rec["action"]
    assert "target-role" in rec["action"]
    assert "aws iam update-assume-role-policy" in rec["command"]


def test_format_remediation_pass_role():
    G = nx.DiGraph()
    G.add_node("arn:role/a", type="aws_role", name="role-a")
    G.add_node("arn:role/b", type="aws_role", name="role-b", is_admin=True)
    G.add_edge("arn:role/a", "arn:role/b", type="iam:PassRole")

    rec = format_remediation("arn:role/a", "arn:role/b", "iam:PassRole", G)
    assert "iam:PassRole" in rec["action"]
    assert "role-a" in rec["action"]
    assert "role-b" in rec["action"]


def test_format_remediation_unknown_edge_type_falls_back_to_generic():
    G = nx.DiGraph()
    G.add_node("a", type="aws_role", name="a")
    G.add_node("b", type="aws_role", name="b")
    G.add_edge("a", "b", type="totally_new_edge_type")

    rec = format_remediation("a", "b", "totally_new_edge_type", G)
    assert rec["edge_type"] == "totally_new_edge_type"
    assert "a" in rec["action"]
    assert "b" in rec["action"]


def test_find_minimum_remediation_simple_irsa_path():
    # Mirrors Benchmark 1: single edge, single path -- the cut must be
    # exactly that one irsa_bridge edge.
    G = nx.DiGraph()
    G.add_node(
        "k8s:sa:default:vulnerable-sa",
        type="k8s_service_account",
        name="vulnerable-sa",
        namespace="default",
    )
    G.add_node("arn:role/admin-role", type="aws_role", name="admin-role", is_admin=True)
    G.add_edge("k8s:sa:default:vulnerable-sa", "arn:role/admin-role", type="irsa_bridge")

    paths = [
        {
            "start": "k8s:sa:default:vulnerable-sa",
            "end": "arn:role/admin-role",
            "path": ["k8s:sa:default:vulnerable-sa", "arn:role/admin-role"],
            "hops": 1,
            "cross_layer": True,
        }
    ]

    recommendations = find_minimum_remediation(G, paths)
    assert len(recommendations) == 1
    assert "vulnerable-sa" in recommendations[0]["action"]
    assert recommendations[0]["edge_type"] == "irsa_bridge"


def test_find_minimum_remediation_finds_bottleneck_in_multihop_path():
    # Mirrors Benchmark 2: SA -> role-a -> role-b -> admin.
    # All 3 edges are on the only path, so the minimum cut is exactly 1
    # edge (any single edge breaks the whole chain) -- not all 3.
    G = nx.DiGraph()
    G.add_node(
        "k8s:sa:default:vulnerable-sa",
        type="k8s_service_account",
        name="vulnerable-sa",
        namespace="default",
    )
    G.add_node("arn:role/role-a", type="aws_role", name="role-a")
    G.add_node("arn:role/role-b", type="aws_role", name="role-b")
    G.add_node("arn:role/admin-role", type="aws_role", name="admin-role", is_admin=True)

    G.add_edge("k8s:sa:default:vulnerable-sa", "arn:role/role-a", type="irsa_bridge")
    G.add_edge("arn:role/role-a", "arn:role/role-b", type="iam:PassRole")
    G.add_edge("arn:role/role-b", "arn:role/admin-role", type="sts:AssumeRole")

    paths = [
        {
            "start": "k8s:sa:default:vulnerable-sa",
            "end": "arn:role/admin-role",
            "path": [
                "k8s:sa:default:vulnerable-sa",
                "arn:role/role-a",
                "arn:role/role-b",
                "arn:role/admin-role",
            ],
            "hops": 3,
            "cross_layer": True,
        }
    ]

    recommendations = find_minimum_remediation(G, paths)
    # KEY assertion: minimum cut on a simple chain is always exactly 1 edge,
    # proving we recommend the SMALLEST fix, not "remove everything".
    assert len(recommendations) == 1


def test_find_minimum_remediation_deduplicates_shared_bottleneck():
    # Two different paths that both flow through the same irsa_bridge edge
    # -- removing that one edge fixes both, so we should see ONE
    # recommendation, not two duplicate ones.
    G = nx.DiGraph()
    G.add_node("k8s:sa:default:sa-1", type="k8s_service_account", name="sa-1", namespace="default")
    G.add_node("arn:role/shared-role", type="aws_role", name="shared-role")
    G.add_node("arn:role/admin-a", type="aws_role", name="admin-a", is_admin=True)
    G.add_node("arn:role/admin-b", type="aws_role", name="admin-b", is_admin=True)

    G.add_edge("k8s:sa:default:sa-1", "arn:role/shared-role", type="irsa_bridge")
    G.add_edge("arn:role/shared-role", "arn:role/admin-a", type="sts:AssumeRole")
    G.add_edge("arn:role/shared-role", "arn:role/admin-b", type="sts:AssumeRole")

    paths = [
        {
            "start": "k8s:sa:default:sa-1",
            "end": "arn:role/admin-a",
            "path": ["k8s:sa:default:sa-1", "arn:role/shared-role", "arn:role/admin-a"],
            "hops": 2,
            "cross_layer": True,
        },
        {
            "start": "k8s:sa:default:sa-1",
            "end": "arn:role/admin-b",
            "path": ["k8s:sa:default:sa-1", "arn:role/shared-role", "arn:role/admin-b"],
            "hops": 2,
            "cross_layer": True,
        },
    ]

    recommendations = find_minimum_remediation(G, paths)
    # Both paths share the same bottleneck (sa-1 -> shared-role), so the
    # minimum cut for both is that single irsa_bridge edge -> 1 unique rec.
    assert len(recommendations) == 1
    assert "sa-1" in recommendations[0]["action"]


def test_find_minimum_remediation_empty_paths_returns_empty_list():
    G = nx.DiGraph()
    G.add_node("a", type="aws_role")
    assert find_minimum_remediation(G, []) == []
