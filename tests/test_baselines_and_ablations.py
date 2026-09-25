"""Tests for the naive baseline and min-cut ablations."""
import networkx as nx

from evaluation.baselines_and_ablations.mincut_vs_greedy import (
    ablation_1, ablation_2, ablation_2b, ablation_2c, build, shared_bottleneck_case,
)
from evaluation.baselines_and_ablations.naive_baseline import naive_flags


def test_naive_flags_true_only_for_admin_role_on_entry_sa():
    case = {"entry_sa": "sa1", "sa_role_map": {"sa1": "r1"},
           "roles": [{"RoleName": "r1", "is_admin": True}]}
    assert naive_flags(case) is True
    case2 = {"entry_sa": "sa1", "sa_role_map": {"sa1": "r1"},
            "roles": [{"RoleName": "r1", "is_admin": False}]}
    assert naive_flags(case2) is False


def test_naive_flags_false_when_entry_sa_unmapped():
    assert naive_flags({"entry_sa": "sa1", "sa_role_map": {}, "roles": []}) is False


def test_ablation_1_mincut_beats_greedy_and_scales():
    results = list(ablation_1())
    for r in results:
        assert r["mincut_edge_count"] == 1, "shared bottleneck must collapse to exactly one cut edge"
        assert r["greedy_edge_count"] == r["n_entries"], "greedy scales linearly by construction"
        assert r["mincut_edge_count"] < r["greedy_edge_count"]


def test_ablation_2_alternate_route_is_also_severed():
    r = ablation_2()
    assert r["paths_found_for_this_source_admin_pair_by_pathfinder"] == 1
    assert r["reported_path_set_contained_only_the_shortest_route"] is True
    assert r["long_route_(4_hop)_present_in_full_graph"] is True
    assert r["src_still_connected_to_target_after_applying_the_computed_cut"] is False


def test_ablation_2b_unreported_pair_still_severed():
    r = ablation_2b()
    assert r["cross_pair_(sa_x_to_admin_y)_individually_reported_by_pathfinder"] is False
    assert r["cross_pair_(sa_x_to_admin_y)_actually_connects_in_full_graph"] is True
    assert r["cross_pair_severed_by_the_computed_cut_despite_never_being_reported"] is True


def test_ablation_2c_disjoint_chains_need_two_cuts():
    r = ablation_2c()
    assert r["correctly_requires_two_separate_cuts"] is True
    assert r["min_cut_edge_count"] == 2


def test_shared_bottleneck_case_graph_shape():
    roles, maps, sas = shared_bottleneck_case(3)
    G, paths = build(roles, maps, sas)
    assert len(paths) == 3
    assert all(p["path"][-1].endswith("shared-admin") for p in paths)


def test_risk_score_decoupled_from_remediation_output():
    """The core correctness claim -- risk_score never affects the set of
    edges min-cut remediation selects, only display order/values."""
    from evaluation.risk_score.decoupling_proof import main as decoupling_main
    out = decoupling_main()
    assert out["all_cases_remediation_invariant_to_risk_weights"] is True
    for case in out["cases"]:
        assert case["remediation_identical_across_all_weight_sets"] is True


def test_risk_score_decoupling_detects_a_real_regression():
    """Sanity check that the decoupling proof can actually fail: rig
    remediation to keep only the HIGHEST-scored path (simulating a
    risk-score-dependent implementation), on the disjoint-chains fixture
    where the two paths cut entirely different edges. Under the
    'production' weights vs the 'adversarial_inverted' weights, the two
    paths' relative order flips (checked explicitly below), so the rigged
    remediation keeps a DIFFERENT single edge under each weighting -- the
    harness must report cut sets that differ, proving it is not just
    passing trivially."""
    import evaluation.risk_score.decoupling_proof as decoupling_mod
    from evaluation.risk_score.decoupling_proof import WEIGHT_SETS, edges_for_weights
    from evaluation.baselines_and_ablations.mincut_vs_greedy import (
        build, role, oidc_trust, svc_trust, allow, sa as sa_node, arn, ADMIN,
    )
    from scoring import risk as scoring_risk

    # Two disjoint chains with DELIBERATELY different edge-type composition,
    # so production weights (PassRole 2.5 > AssumeRole 2.0) and the inverted
    # weights (AssumeRole 3.0 > PassRole 1.5) rank them oppositely.
    admin_p = role("admin-p2", svc_trust("ec2.amazonaws.com"), [ADMIN], admin=True)
    admin_q = role("admin-q2", {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": arn("mid-q2")}, "Action": "sts:AssumeRole"}]},
        [ADMIN], admin=True)
    entry_p = role("entry-p2", oidc_trust("sa-p2", "default"),
                   [allow("iam:PassRole", arn("admin-p2")), allow("ec2:RunInstances")])
    entry_q = role("entry-q2", oidc_trust("sa-q2", "default"), [allow("sts:AssumeRole", arn("mid-q2"))])
    mid_q = role("mid-q2", {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": arn("entry-q2")}, "Action": "sts:AssumeRole"}]},
        [allow("sts:AssumeRole", arn("admin-q2"))])
    roles = [admin_p, admin_q, entry_p, entry_q, mid_q]
    maps = [{"service_account": "sa-p2", "namespace": "default", "aws_role_arn": arn("entry-p2")},
           {"service_account": "sa-q2", "namespace": "default", "aws_role_arn": arn("entry-q2")}]
    sas = [sa_node("sa-p2", "default"), sa_node("sa-q2", "default")]
    G, paths = build(roles, maps, sas)

    # Confirm the two production-vs-inverted weightings actually flip which
    # path scores higher, or this test would prove nothing.
    def top_path_edge_type(weights):
        original = dict(scoring_risk.PERMISSION_WEIGHTS)
        scoring_risk.PERMISSION_WEIGHTS.clear()
        scoring_risk.PERMISSION_WEIGHTS.update(weights)
        try:
            scored = scoring_risk.score_all_paths(G, [dict(p) for p in paths])
        finally:
            scoring_risk.PERMISSION_WEIGHTS.clear()
            scoring_risk.PERMISSION_WEIGHTS.update(original)
        top = max(scored, key=lambda p: p["risk_score"])
        return top["path"][0]   # the two paths have distinct sources (sa-p vs sa-q)

    top_prod = top_path_edge_type(WEIGHT_SETS["production"])
    top_inv = top_path_edge_type(WEIGHT_SETS["adversarial_inverted"])
    assert top_prod != top_inv, "fixture/weight choice must actually flip the top-ranked path, or this test is vacuous"

    real_fn = decoupling_mod.find_minimum_remediation

    def rigged(G, paths):
        if not paths:
            return []
        best = max(paths, key=lambda p: p.get("risk_score", 0))
        return real_fn(G, [best])

    decoupling_mod.find_minimum_remediation = rigged
    try:
        cut_a, _ = edges_for_weights(G, paths, WEIGHT_SETS["production"])
        cut_b, _ = edges_for_weights(G, paths, WEIGHT_SETS["adversarial_inverted"])
    finally:
        decoupling_mod.find_minimum_remediation = real_fn

    assert cut_a != cut_b, "rigged (risk-score-dependent) remediation must produce different cuts here"
    assert len(cut_a) == 1 and len(cut_b) == 1
