"""End-to-end tests of the evaluator through graph building, pathfinding and remediation."""

import types

from graph.builder import build_unified_graph
from ingestion import policy_eval as pe
from pathfinder.search import annotate_path_confidence, find_all_cross_layer_paths
from remediation.engine import find_minimum_remediation

A = "000000000000"
OIDC = f"arn:aws:iam::{A}:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/ABC"
K = "oidc.eks.us-east-1.amazonaws.com/id/ABC"
ADMIN_STMT = {"Effect": "Allow", "Action": "*", "Resource": "*"}


def arn(n): return f"arn:aws:iam::{A}:role/{n}"


def irsa_trust(ns="default", sa="app"):
    return {"Statement": [{"Effect": "Allow", "Principal": {"Federated": OIDC},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {"StringEquals": {f"{K}:sub": f"system:serviceaccount:{ns}:{sa}",
                                           f"{K}:aud": "sts.amazonaws.com"}}}]}


EC2 = {"Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}


def role(name, trust, docs=None, admin=False):
    return {"Arn": arn(name), "RoleName": name, "is_admin": admin,
            "AssumeRolePolicyDocument": trust, "policy_documents": docs or [],
            "trust_principals": [], "passrole_resources": []}


def sa(name, ns="default"):
    o = types.SimpleNamespace(); o.metadata = types.SimpleNamespace(name=name, namespace=ns, annotations=None)
    return o


def k8s(*sas):
    return {"service_accounts": list(sas), "roles": [], "role_bindings": [],
            "cluster_roles": [], "cluster_role_bindings": []}


def mapping(sa_name, role_name, ns="default"):
    return {"service_account": sa_name, "namespace": ns, "aws_role_arn": arn(role_name)}


def run(aws, k, maps, cfg=None):
    G = build_unified_graph(aws, k, maps, config=cfg)
    return G, annotate_path_confidence(G, find_all_cross_layer_paths(G))


def test_direct_irsa_admin_valid_trust_is_confirmed():
    aws = {"users": [], "groups": [], "roles": [role("admin", irsa_trust(), [{"Statement": [ADMIN_STMT]}], admin=True)]}
    G, paths = run(aws, k8s(sa("app")), [mapping("app", "admin")])
    assert len(paths) == 1 and paths[0]["confidence"] == "confirmed" and paths[0]["irsa_trust"] == "valid"


def test_ec2_trusted_admin_via_irsa_annotate_vs_strict():
    aws = {"users": [], "groups": [], "roles": [role("admin", EC2, [{"Statement": [ADMIN_STMT]}], admin=True)]}
    _, p_annot = run(aws, k8s(sa("app")), [mapping("app", "admin")], pe.ANNOTATE)
    assert len(p_annot) == 1 and p_annot[0]["confidence"] == "unresolved" and p_annot[0]["irsa_trust"] == "invalid"
    G, p_strict = run(aws, k8s(sa("app")), [mapping("app", "admin")])   # default == strict
    assert p_strict == [] and G.graph["suppressed_edges"][0]["type"] == "irsa_bridge"
    _, p_legacy = run(aws, k8s(sa("app")), [mapping("app", "admin")], pe.LEGACY)
    assert len(p_legacy) == 1


def test_wrong_subject_trust_is_invalid_in_strict():
    aws = {"users": [], "groups": [], "roles": [role("admin", irsa_trust(sa="other"), admin=True)]}
    _, p = run(aws, k8s(sa("app")), [mapping("app", "admin")], pe.STRICT)
    assert p == []


def test_explicit_deny_all_makes_admin_inert():
    docs = [{"Statement": [ADMIN_STMT, {"Effect": "Deny", "Action": "*", "Resource": "*"}]}]
    aws = {"users": [], "groups": [], "roles": [role("dead-admin", irsa_trust(), docs, admin=True)]}
    _, p = run(aws, k8s(sa("app")), [mapping("app", "dead-admin")])
    assert p == []
    _, p_legacy = run(aws, k8s(sa("app")), [mapping("app", "dead-admin")], pe.LEGACY)
    assert len(p_legacy) == 1


def test_mfa_gated_irsa_role_is_invalid():
    trust = {"Statement": [{"Effect": "Allow", "Principal": {"Federated": OIDC},
             "Action": "sts:AssumeRoleWithWebIdentity",
             "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}]}
    aws = {"users": [], "groups": [], "roles": [role("mfa-admin", trust, admin=True)]}
    _, p = run(aws, k8s(sa("app")), [mapping("app", "mfa-admin")], pe.STRICT)
    assert p == []


def test_passrole_bare_is_potential_and_paired_is_confirmed():
    pr = {"Effect": "Allow", "Action": "iam:PassRole", "Resource": arn("admin")}
    ec2 = {"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"}
    for docs, want in (([{"Statement": [pr]}], "potential"), ([{"Statement": [pr, ec2]}], "confirmed")):
        aws = {"users": [], "groups": [], "roles": [
            role("entry", irsa_trust(), docs), role("admin", EC2, [{"Statement": [ADMIN_STMT]}], admin=True)]}
        _, p = run(aws, k8s(sa("app")), [mapping("app", "entry")])
        assert len(p) == 1 and p[0]["confidence"] == want, (want, p)


def test_passrole_glob_resource_now_detected():
    pr = {"Effect": "Allow", "Action": "iam:PassRole", "Resource": f"arn:aws:iam::{A}:role/app-*"}
    aws = {"users": [], "groups": [], "roles": [
        role("entry", irsa_trust(), [{"Statement": [pr]}]),
        role("app-admin", EC2, [{"Statement": [ADMIN_STMT]}], admin=True)]}
    # legacy path: entity has legacy passrole_resources only -> glob literal, missed
    aws["roles"][0]["passrole_resources"] = [pr["Resource"]]
    _, legacy = run(aws, k8s(sa("app")), [mapping("app", "entry")], pe.LEGACY)
    _, new = run(aws, k8s(sa("app")), [mapping("app", "entry")])
    assert legacy == [] and len(new) == 1


def test_passrole_explicit_deny_suppresses_edge():
    docs = [{"Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
                           {"Effect": "Deny", "Action": "iam:PassRole", "Resource": arn("admin")}]}]
    aws = {"users": [], "groups": [], "roles": [
        role("entry", irsa_trust(), docs), role("admin", EC2, [{"Statement": [ADMIN_STMT]}], admin=True)]}
    G, p = run(aws, k8s(sa("app")), [mapping("app", "entry")])
    assert p == [] and any(s["reason"] == "explicit Deny on iam:PassRole" for s in G.graph["suppressed_edges"])


def test_wildcard_trust_admin_reached_when_caller_may_assume():
    wt = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]}
    can = [{"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}]}]
    aws = {"users": [], "groups": [], "roles": [
        role("entry", irsa_trust(), can), role("open-admin", wt, [{"Statement": [ADMIN_STMT]}], admin=True)]}
    G, p = run(aws, k8s(sa("app")), [mapping("app", "entry")])
    assert len(p) == 1 and p[0]["confidence"] == "confirmed"
    assert G.graph["wildcard_trust_roles"][0]["status"] == "unrestricted"
    # caller without sts:AssumeRole permission: no path
    aws["roles"][0]["policy_documents"] = []
    _, p2 = run(aws, k8s(sa("app")), [mapping("app", "entry")])
    assert p2 == []
    # legacy: wildcard trust invisible either way
    aws["roles"][0]["policy_documents"] = can
    _, p3 = run(aws, k8s(sa("app")), [mapping("app", "entry")], pe.LEGACY)
    assert p3 == []


def test_conditioned_wildcard_trust_is_unresolved():
    wt = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole",
                         "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc"}}}]}
    can = [{"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}]}]
    aws = {"users": [], "groups": [], "roles": [
        role("entry", irsa_trust(), can), role("org-admin", wt, [{"Statement": [ADMIN_STMT]}], admin=True)]}
    _, p = run(aws, k8s(sa("app")), [mapping("app", "entry")])
    assert len(p) == 1 and p[0]["confidence"] == "unresolved"


def test_parallel_mechanisms_recorded_and_remediated():
    pr = {"Effect": "Allow", "Action": "iam:PassRole", "Resource": arn("admin")}
    admin_trust = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": arn("entry")}, "Action": "sts:AssumeRole"},
                                 {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    aws = {"users": [], "groups": [], "roles": [
        role("entry", irsa_trust(), [{"Statement": [pr]}]),
        role("admin", admin_trust, [{"Statement": [ADMIN_STMT]}], admin=True)]}
    G, p = run(aws, k8s(sa("app")), [mapping("app", "entry")])
    e = G.edges[arn("entry"), arn("admin")]
    assert set(e["edge_types"]) == {"sts:AssumeRole", "iam:PassRole"}
    assert e["confidence"] == "confirmed"          # AssumeRole trust is sufficient on its own
    recs = find_minimum_remediation(G, p)
    types_fixed = {r["edge_type"] for r in recs if r["target"] == arn("admin")}
    assert types_fixed == {"sts:AssumeRole", "iam:PassRole"}


def test_partial_deny_annotates_but_keeps_admin():
    docs = [{"Statement": [ADMIN_STMT, {"Effect": "Deny", "Action": "s3:Delete*", "Resource": "*"}]}]
    aws = {"users": [], "groups": [], "roles": [role("a", irsa_trust(), docs, admin=True)]}
    G, p = run(aws, k8s(sa("app")), [mapping("app", "a")])
    assert len(p) == 1 and p[0]["sink_admin_status"] == "full_partial_deny"


def test_conditional_deny_makes_sink_unresolved():
    docs = [{"Statement": [ADMIN_STMT, {"Effect": "Deny", "Action": "*", "Resource": "*",
             "Condition": {"IpAddress": {"aws:SourceIp": "1.2.3.4/32"}}}]}]
    aws = {"users": [], "groups": [], "roles": [role("a", irsa_trust(), docs, admin=True)]}
    _, p = run(aws, k8s(sa("app")), [mapping("app", "a")])
    assert len(p) == 1 and p[0]["confidence"] == "unresolved"
