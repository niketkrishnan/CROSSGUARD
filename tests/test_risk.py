"""Tests for scoring/risk.py -- risk scoring of escalation paths."""

import networkx as nx

from scoring.risk import score_all_paths, score_path


def test_score_path_simple_irsa_bridge():
    # Mirrors Benchmark 1: 1 hop, irsa_bridge, cross-layer.
    G = nx.DiGraph()
    G.add_node("sa-1", type="k8s_service_account")
    G.add_node("role-a", type="aws_role", is_admin=True)
    G.add_edge("sa-1", "role-a", type="irsa_bridge")

    path_dict = {"path": ["sa-1", "role-a"], "hops": 1, "cross_layer": True}
    score = score_path(G, path_dict)

    # edge_score = 3.0 (irsa_bridge weight), hop_count = 1, cross_layer_bonus = 2.0
    # score = (3.0 / 1) * 2.0 = 6.0
    assert score == 6.0


def test_score_path_zero_hops_returns_zero_not_crash():
    G = nx.DiGraph()
    G.add_node("sa-1", type="k8s_service_account")
    path_dict = {"path": ["sa-1"], "hops": 0, "cross_layer": False}
    assert score_path(G, path_dict) == 0.0


def test_score_path_multi_hop_lower_than_single_hop_same_edges():
    # Same total edge weight, but spread over more hops -> lower score.
    # This proves the "shorter path = scarier" intuition from the brief.
    G = nx.DiGraph()
    G.add_node("sa-1", type="k8s_service_account")
    G.add_node("role-a", type="aws_role")
    G.add_node("role-b", type="aws_role")
    G.add_node("role-c", type="aws_role", is_admin=True)

    G.add_edge("sa-1", "role-a", type="irsa_bridge")
    G.add_edge("role-a", "role-b", type="iam:PassRole")
    G.add_edge("role-b", "role-c", type="sts:AssumeRole")

    short_path = {"path": ["sa-1", "role-a"], "hops": 1, "cross_layer": True}
    long_path = {
        "path": ["sa-1", "role-a", "role-b", "role-c"],
        "hops": 3,
        "cross_layer": True,
    }

    short_score = score_path(G, short_path)
    long_score = score_path(G, long_path)

    assert short_score > long_score


def test_score_path_cross_layer_scores_higher_than_same_layer():
    # Identical edge type and hop count, only difference is cross_layer flag.
    G = nx.DiGraph()
    G.add_node("a", type="aws_role")
    G.add_node("b", type="aws_role", is_admin=True)
    G.add_edge("a", "b", type="sts:AssumeRole")

    cross_layer_path = {"path": ["a", "b"], "hops": 1, "cross_layer": True}
    same_layer_path = {"path": ["a", "b"], "hops": 1, "cross_layer": False}

    assert score_path(G, cross_layer_path) > score_path(G, same_layer_path)


def test_score_path_unknown_edge_type_uses_default_weight():
    G = nx.DiGraph()
    G.add_node("a", type="k8s_service_account")
    G.add_node("b", type="aws_role", is_admin=True)
    G.add_edge("a", "b", type="some_future_edge_type_we_havent_weighted_yet")

    path_dict = {"path": ["a", "b"], "hops": 1, "cross_layer": True}
    # default weight 1.0, cross_layer bonus 2.0 -> score = 2.0
    assert score_path(G, path_dict) == 2.0


def test_score_path_missing_cross_layer_key_defaults_to_false():
    G = nx.DiGraph()
    G.add_node("a", type="k8s_service_account")
    G.add_node("b", type="aws_role", is_admin=True)
    G.add_edge("a", "b", type="irsa_bridge")

    # no "cross_layer" key at all
    path_dict = {"path": ["a", "b"], "hops": 1}
    score = score_path(G, path_dict)
    # should use SAME_LAYER_BONUS (1.0), not crash: (3.0/1) * 1.0 = 3.0
    assert score == 3.0


def test_score_all_paths_sorts_highest_risk_first():
    G = nx.DiGraph()
    G.add_node("sa-1", type="k8s_service_account")
    G.add_node("sa-2", type="k8s_service_account")
    G.add_node("role-low", type="aws_role")
    G.add_node("role-admin", type="aws_role", is_admin=True)

    # sa-1: high risk -- direct irsa_bridge, cross-layer
    G.add_edge("sa-1", "role-admin", type="irsa_bridge")
    # sa-2: lower risk -- weaker edge type, same-layer flag
    G.add_edge("sa-2", "role-low", type="group_membership")
    G.add_edge("role-low", "role-admin", type="sts:AssumeRole")

    paths = [
        {"path": ["sa-1", "role-admin"], "hops": 1, "cross_layer": True, "start": "sa-1"},
        {
            "path": ["sa-2", "role-low", "role-admin"],
            "hops": 2,
            "cross_layer": True,
            "start": "sa-2",
        },
    ]

    scored = score_all_paths(G, paths)

    assert len(scored) == 2
    assert scored[0]["risk_score"] >= scored[1]["risk_score"]
    assert scored[0]["start"] == "sa-1"  # the more dangerous one comes first
    assert "risk_score" in scored[0] and "risk_score" in scored[1]
