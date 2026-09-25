"""
evaluation/baselines_and_ablations/mincut_vs_greedy.py

Ablation 1: does the global min-cut (remediation/engine.py, C4) actually
beat a naive greedy remediation -- remove one edge per found path,
independently, with no shared-bottleneck reasoning -- on cases built
specifically to have a shared bottleneck? The paper's own B6/B8 benchmarks
already assert this qualitatively ("2 paths closed by a single fix").
This module makes it a direct, code-measured comparison: same paths in,
compare edge-removal COUNTS between the two strategies.

Ablation 2: reported-path-only vs full-path-space. Algorithm 1 (BFS,
Section III-G) returns the SHORTEST path per (K8s-source, admin) pair; the
paper's own Section III-H already states the min-cut "is not guaranteed"
to sever an alternate, longer route to the same pair that exists outside
the reported path set P. This module builds a case with exactly that
property and CONFIRMS the gap empirically (cutting the reported path's
edges leaves the alternate route open), rather than leaving it as an
unverified prose caveat.

    python -m evaluation.baselines_and_ablations.mincut_vs_greedy
"""

from __future__ import annotations

import json
import logging
import types

logging.disable(logging.WARNING)

import networkx as nx  # noqa: E402

from graph.builder import build_unified_graph  # noqa: E402
from ingestion import policy_eval as pe  # noqa: E402
from pathfinder.search import annotate_path_confidence, find_all_cross_layer_paths  # noqa: E402
from remediation.engine import find_minimum_remediation  # noqa: E402

ACCOUNT = "000000000000"
OIDC_HOST = "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"
OIDC_PROVIDER_ARN = f"arn:aws:iam::{ACCOUNT}:oidc-provider/{OIDC_HOST}"
ADMIN = {"Effect": "Allow", "Action": "*", "Resource": "*"}


def arn(n): return f"arn:aws:iam::{ACCOUNT}:role/{n}"


def oidc_trust(sa, ns):
    return {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Federated": OIDC_PROVIDER_ARN},
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Condition": {"StringEquals": {f"{OIDC_HOST}:sub": f"system:serviceaccount:{ns}:{sa}",
                                       f"{OIDC_HOST}:aud": "sts.amazonaws.com"}},
    }]}


def role(name, trust, stmts=None, admin=False):
    return {"Arn": arn(name), "RoleName": name, "is_admin": admin,
            "AssumeRolePolicyDocument": trust, "policy_documents": [{"Statement": stmts}] if stmts else [],
            "trust_principals": [], "passrole_resources": []}


def svc_trust(service):
    return {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]}


def allow(action, resource="*"):
    return {"Effect": "Allow", "Action": action, "Resource": resource}


def sa(name, ns): 
    o = types.SimpleNamespace(); o.metadata = types.SimpleNamespace(name=name, namespace=ns, annotations=None)
    return o


def build(roles, maps, sas):
    aws = {"users": [], "groups": [], "roles": roles}
    k8s = {"service_accounts": sas, "roles": [], "role_bindings": [], "cluster_roles": [], "cluster_role_bindings": []}
    G = build_unified_graph(aws, k8s, maps, config=pe.STRICT)
    paths = annotate_path_confidence(G, find_all_cross_layer_paths(G))
    return G, paths


def greedy_remediation(G, paths):
    """One edge removed per path, chosen independently (the FIRST edge of
    each path), with no cross-path reasoning. This is what "just cut
    something on every reported path" looks like -- the natural thing to
    do WITHOUT solving a global min-cut problem."""
    cut = set()
    for p in paths:
        path = p["path"]
        cut.add((path[0], path[1]))
    return cut


# ---------------------------------------------------------------------------
# Ablation 1: shared bottleneck -- two entry SAs, two DIFFERENT PassRole
# grants, but both routed through the SAME AssumeRole edge into the same
# admin role (a realistic "one over-broad trust relationship shared by many
# callers" scenario).
# ---------------------------------------------------------------------------

def shared_bottleneck_case(n_entries=4):
    """n_entries ServiceAccounts, each via its OWN role, each independently
    permitted (via a distinct PassRole grant naming a DIFFERENT
    intermediate role) to reach ONE shared hop role, which is the only
    thing trusted by the admin role. Cutting the single shared hop->admin
    edge severs ALL n_entries paths at once; a greedy per-path strategy
    that picks each path's first edge would instead remove n_entries
    separate edges (or, if it happened to pick the last edge each time,
    would collapse to the same 1-edge answer only by chance -- this
    generator picks the FIRST edge, which never collapses, to test the
    strategy honestly rather than the best case for it)."""
    roles = []
    maps = []
    sas = []
    admin_role = role("shared-admin", svc_trust("ec2.amazonaws.com"), [ADMIN], admin=True)
    hub_role = role("shared-hub", {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": [arn(f"entry-{i}") for i in range(n_entries)]}, "Action": "sts:AssumeRole"},
    ]}, [allow("iam:PassRole", arn("shared-admin")), allow("ec2:RunInstances")])
    # hub must also be trusted by admin
    admin_role["AssumeRolePolicyDocument"] = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"},
        {"Effect": "Allow", "Principal": {"AWS": arn("shared-hub")}, "Action": "sts:AssumeRole"},
    ]}
    roles += [admin_role, hub_role]
    for i in range(n_entries):
        e_sa, e_role = f"sa-entry-{i}", f"entry-{i}"
        roles.append(role(e_role, oidc_trust(e_sa, "default"), [allow("sts:AssumeRole", arn("shared-hub"))]))
        maps.append({"service_account": e_sa, "namespace": "default", "aws_role_arn": arn(e_role)})
        sas.append(sa(e_sa, "default"))
    return roles, maps, sas


def ablation_1():
    for n in (2, 3, 4, 8):
        roles, maps, sas = shared_bottleneck_case(n)
        G, paths = build(roles, maps, sas)
        mincut = find_minimum_remediation(G, paths)
        mincut_edges = {(r["source"], r["target"]) for r in mincut}
        greedy_edges = greedy_remediation(G, paths)
        yield {"n_entries": n, "n_paths_found": len(paths),
              "mincut_edge_count": len(mincut_edges), "greedy_edge_count": len(greedy_edges),
              "mincut_edges": sorted(f"{u.split(':')[-1]}->{v.split('/')[-1]}" for u, v in mincut_edges),
              "greedy_edges": sorted(f"{u.split(':')[-1]}->{v.split('/')[-1]}" for u, v in greedy_edges)}


# ---------------------------------------------------------------------------
# Ablation 2: reported-shortest-path-only vs full path space.
# Build a 2-hop shortest route AND a genuinely distinct 4-hop alternate
# route from the SAME entry SA to the SAME admin role, using DIFFERENT
# edges throughout. Algorithm 1 (BFS) returns only the shortest; check
# whether the min-cut computed from the reported path set actually leaves
# the alternate route open.
# ---------------------------------------------------------------------------

def alternate_route_case():
    """ONE IRSA-bound entry role ('hub'), branching into two edge-disjoint
    routes to the SAME admin role: a 2-hop direct AssumeRole (hub ->
    target-admin) and a 4-hop chain through three intermediate roles
    (hub -> mid1 -> mid2 -> mid3 -> target-admin). Both routes share only
    the entry node and the target node -- no edges in common -- so this
    tests the actual claim in Section III-H: a longer route to the SAME
    (source, admin) pair, outside the reported shortest-path set P."""
    admin_role = role("target-admin", {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": [arn("hub"), arn("mid3")]}, "Action": "sts:AssumeRole"},
    ]}, [ADMIN], admin=True)
    hub = role("hub", oidc_trust("sa-alt-route", "default"),
              [allow("sts:AssumeRole", arn("target-admin")), allow("sts:AssumeRole", arn("mid1"))])
    mid1 = role("mid1", {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": arn("hub")}, "Action": "sts:AssumeRole"}]},
        [allow("sts:AssumeRole", arn("mid2"))])
    mid2 = role("mid2", {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": arn("mid1")}, "Action": "sts:AssumeRole"}]},
        [allow("sts:AssumeRole", arn("mid3"))])
    mid3 = role("mid3", {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": arn("mid2")}, "Action": "sts:AssumeRole"}]},
        [allow("sts:AssumeRole", arn("target-admin"))])
    roles = [admin_role, hub, mid1, mid2, mid3]
    maps = [{"service_account": "sa-alt-route", "namespace": "default", "aws_role_arn": arn("hub")}]
    sas = [sa("sa-alt-route", "default")]
    return roles, maps, sas


def ablation_2():
    roles, maps, sas = alternate_route_case()
    G, paths = build(roles, maps, sas)
    src, tgt = "k8s:sa:default:sa-alt-route", arn("target-admin")
    same_pair_paths = [p for p in paths if p["path"][0] == src and p["path"][-1] == tgt]
    reported_path = same_pair_paths[0] if same_pair_paths else None
    mincut = find_minimum_remediation(G, paths)
    cut_edges = {(r["source"], r["target"]) for r in mincut}

    # Confirm the long route exists in the FULL graph independent of pathfinder.
    long_route_exists = any(
        nx.has_path(G, src, tgt) and p != reported_path["path"]
        for p in nx.all_simple_paths(G, src, tgt, cutoff=6)
        for _ in [None]
    )
    all_simple_routes = list(nx.all_simple_paths(G, src, tgt, cutoff=6))

    # Apply the computed cut to a COPY of the graph and check if the long
    # route (edge-disjoint from the reported short route by construction)
    # still connects src to tgt.
    G2 = G.copy()
    for u, v in cut_edges:
        if G2.has_edge(u, v):
            G2.remove_edge(u, v)
    still_connected_after_cut = nx.has_path(G2, src, tgt)

    return {
        "paths_found_for_this_source_admin_pair_by_pathfinder": len(same_pair_paths),
        "reported_path_hops": reported_path["hops"] if reported_path else None,
        "all_simple_routes_in_full_graph": [
            [n.split(":")[-1].split("/")[-1] for n in r] for r in all_simple_routes
        ],
        "min_cut_edges": sorted(f"{u.split(':')[-1]}->{v.split('/')[-1]}" for u, v in cut_edges),
        "long_route_(4_hop)_present_in_full_graph": len(all_simple_routes) > 1,
        "reported_path_set_contained_only_the_shortest_route": len(same_pair_paths) == 1,
        "src_still_connected_to_target_after_applying_the_computed_cut": still_connected_after_cut,
    }


# ---------------------------------------------------------------------------
# Ablation 2b: does the min-cut ALSO sever a route between a (source, admin)
# pair that was NEVER individually reported, as long as that source and
# that admin each individually appear as the endpoint of SOME OTHER reported
# path? _build_super_graph attaches super-source to every reported path's
# START node and super-sink to every reported path's END node, then computes
# ONE min s*-t* cut over the graph's REAL edges -- which treats all reported
# starts as one combined source and all reported ends as one combined sink.
# If that is right, a totally unreported (source_A, admin_B) connection
# should still be severed whenever source_A and admin_B each show up as the
# endpoint of some OTHER path in P.
# ---------------------------------------------------------------------------

def unreported_pair_case():
    """Two independent (source, admin) pairs are the ones pathfinder
    reports: (sa-x -> admin-x) and (sa-y -> admin-y). A THIRD, entirely
    separate route (sa-x -> admin-y) is wired in using fresh intermediate
    roles, sharing no edges with either reported path -- and is never
    reported on its own only because Algorithm 1 already found sa-x's
    shortest path to admin-x, and BFS-per-source stops at the first found
    admin per source in this construction (each source's role only leads
    toward its OWN admin's chain plus, separately, the cross-pair chain)."""
    admin_x = role("admin-x", svc_trust("ec2.amazonaws.com"), [ADMIN], admin=True)
    admin_y = role("admin-y", {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"},
        {"Effect": "Allow", "Principal": {"AWS": arn("cross-hop-2")}, "Action": "sts:AssumeRole"},
    ]}, [ADMIN], admin=True)
    entry_x = role("entry-x", oidc_trust("sa-x", "default"),
                   [allow("iam:PassRole", arn("admin-x")), allow("ec2:RunInstances"),
                    allow("sts:AssumeRole", arn("cross-hop-1"))])
    entry_y = role("entry-y", oidc_trust("sa-y", "default"), [allow("iam:PassRole", arn("admin-y")), allow("ec2:RunInstances")])
    cross1 = role("cross-hop-1", {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": arn("entry-x")}, "Action": "sts:AssumeRole"}]},
        [allow("sts:AssumeRole", arn("cross-hop-2"))])
    cross2 = role("cross-hop-2", {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": arn("cross-hop-1")}, "Action": "sts:AssumeRole"}]},
        [allow("sts:AssumeRole", arn("admin-y"))])
    roles = [admin_x, admin_y, entry_x, entry_y, cross1, cross2]
    maps = [{"service_account": "sa-x", "namespace": "default", "aws_role_arn": arn("entry-x")},
           {"service_account": "sa-y", "namespace": "default", "aws_role_arn": arn("entry-y")}]
    sas = [sa("sa-x", "default"), sa("sa-y", "default")]
    return roles, maps, sas


def ablation_2b():
    roles, maps, sas = unreported_pair_case()
    G, paths = build(roles, maps, sas)
    src_x, tgt_x = "k8s:sa:default:sa-x", arn("admin-x")
    src_x_node, tgt_y = "k8s:sa:default:sa-x", arn("admin-y")

    reported_pairs = {(p["path"][0], p["path"][-1]) for p in paths}
    cross_pair_reported = (src_x_node, tgt_y) in reported_pairs
    cross_pair_connects = nx.has_path(G, src_x_node, tgt_y)

    mincut = find_minimum_remediation(G, paths)
    cut_edges = {(r["source"], r["target"]) for r in mincut}
    G2 = G.copy()
    for u, v in cut_edges:
        if G2.has_edge(u, v):
            G2.remove_edge(u, v)
    cross_pair_severed = not nx.has_path(G2, src_x_node, tgt_y)

    return {
        "reported_pairs": sorted(f"{u.split(':')[-1]}->{v.split('/')[-1]}" for u, v in reported_pairs),
        "cross_pair_(sa_x_to_admin_y)_individually_reported_by_pathfinder": cross_pair_reported,
        "cross_pair_(sa_x_to_admin_y)_actually_connects_in_full_graph": cross_pair_connects,
        "min_cut_edges": sorted(f"{u.split(':')[-1]}->{v.split('/')[-1]}" for u, v in cut_edges),
        "cross_pair_severed_by_the_computed_cut_despite_never_being_reported": cross_pair_severed,
    }


# ---------------------------------------------------------------------------
# Ablation 2c (sanity check on 2b): two FULLY DISJOINT escalation chains
# (no shared node at all) must require TWO separate cut edges, not one --
# confirming the min-cut isn't trivially always finding a single edge
# regardless of topology, which would undermine the 2/2b results above.
# ---------------------------------------------------------------------------

def disjoint_case():
    admin_p = role("admin-p", svc_trust("ec2.amazonaws.com"), [ADMIN], admin=True)
    admin_q = role("admin-q", svc_trust("ec2.amazonaws.com"), [ADMIN], admin=True)
    entry_p = role("entry-p", oidc_trust("sa-p", "default"), [allow("iam:PassRole", arn("admin-p")), allow("ec2:RunInstances")])
    entry_q = role("entry-q", oidc_trust("sa-q", "default"), [allow("iam:PassRole", arn("admin-q")), allow("ec2:RunInstances")])
    roles = [admin_p, admin_q, entry_p, entry_q]
    maps = [{"service_account": "sa-p", "namespace": "default", "aws_role_arn": arn("entry-p")},
           {"service_account": "sa-q", "namespace": "default", "aws_role_arn": arn("entry-q")}]
    sas = [sa("sa-p", "default"), sa("sa-q", "default")]
    return roles, maps, sas


def ablation_2c():
    roles, maps, sas = disjoint_case()
    G, paths = build(roles, maps, sas)
    mincut = find_minimum_remediation(G, paths)
    cut_edges = {(r["source"], r["target"]) for r in mincut}
    return {"n_paths": len(paths), "min_cut_edge_count": len(cut_edges),
           "min_cut_edges": sorted(f"{u.split(':')[-1]}->{v.split('/')[-1]}" for u, v in cut_edges),
           "correctly_requires_two_separate_cuts": len(cut_edges) == 2}


def main():
    a1 = list(ablation_1())
    a2 = ablation_2()
    a2b = ablation_2b()
    a2c = ablation_2c()
    out = {"ablation_1_mincut_vs_greedy": a1, "ablation_2_reported_vs_full_path_space": a2,
          "ablation_2b_unreported_pair_still_severed": a2b,
          "ablation_2c_disjoint_chains_need_two_cuts_sanity_check": a2c}
    print(json.dumps(out, indent=1))
    with open("evaluation/baselines_and_ablations/mincut_ablation_results.json", "w") as f:
        json.dump(out, f, indent=1)
    return out


if __name__ == "__main__":
    main()
