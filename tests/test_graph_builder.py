"""Tests for graph/builder.py -- the unified cross-layer graph (C1),
including the IRSA bridge edge (C2). Uses small synthetic AWS/K8s data
so these tests don't need LocalStack or Minikube running."""

import types

from graph.builder import build_unified_graph


def _fake_sa(name, namespace="default", annotations=None):
    sa = types.SimpleNamespace()
    sa.metadata = types.SimpleNamespace()
    sa.metadata.name = name
    sa.metadata.namespace = namespace
    sa.metadata.annotations = annotations
    return sa


def _empty_aws_data():
    return {"users": [], "roles": [], "groups": []}


def _empty_k8s_data():
    return {
        "service_accounts": [],
        "roles": [],
        "role_bindings": [],
        "cluster_roles": [],
        "cluster_role_bindings": [],
    }


def test_simple_irsa_bridge_creates_cross_layer_edge():
    # Mirrors Benchmark 1: one SA, one admin role, IRSA bridge between them.
    aws_data = _empty_aws_data()
    aws_data["roles"] = [
        {
            "Arn": "arn:aws:iam::000000000000:role/admin-role",
            "RoleName": "admin-role",
            "is_admin": True,
            "trust_principals": [],
            "passrole_resources": [],
        }
    ]

    k8s_data = _empty_k8s_data()
    k8s_data["service_accounts"] = [_fake_sa("vulnerable-sa", "default")]

    irsa_mappings = [
        {
            "service_account": "vulnerable-sa",
            "namespace": "default",
            "aws_role_arn": "arn:aws:iam::000000000000:role/admin-role",
        }
    ]

    G = build_unified_graph(aws_data, k8s_data, irsa_mappings)

    assert G.has_node("k8s:sa:default:vulnerable-sa")
    assert G.has_node("arn:aws:iam::000000000000:role/admin-role")
    assert G.has_edge("k8s:sa:default:vulnerable-sa", "arn:aws:iam::000000000000:role/admin-role")

    edge_data = G.edges["k8s:sa:default:vulnerable-sa", "arn:aws:iam::000000000000:role/admin-role"]
    assert edge_data["type"] == "irsa_bridge"


def test_irsa_mapping_to_missing_role_does_not_crash():
    # If the annotation points at a role we never ingested (e.g. permission
    # error during ingestion), we should skip it gracefully, not crash.
    aws_data = _empty_aws_data()
    k8s_data = _empty_k8s_data()
    k8s_data["service_accounts"] = [_fake_sa("orphan-sa", "default")]

    irsa_mappings = [
        {
            "service_account": "orphan-sa",
            "namespace": "default",
            "aws_role_arn": "arn:aws:iam::000000000000:role/does-not-exist",
        }
    ]

    G = build_unified_graph(aws_data, k8s_data, irsa_mappings)
    assert G.number_of_edges() == 0  # no crash, just no edge added


def test_passrole_wildcard_creates_edges_to_all_roles():
    aws_data = _empty_aws_data()
    aws_data["roles"] = [
        {
            "Arn": "arn:aws:iam::000000000000:role/role-a",
            "RoleName": "role-a",
            "is_admin": False,
            "trust_principals": [],
            "passrole_resources": ["*"],
        },
        {
            "Arn": "arn:aws:iam::000000000000:role/role-b",
            "RoleName": "role-b",
            "is_admin": True,
            "trust_principals": [],
            "passrole_resources": [],
        },
    ]
    k8s_data = _empty_k8s_data()

    G = build_unified_graph(aws_data, k8s_data, [])

    # role-a has PassRole on "*" -> should reach role-b, but not itself
    assert G.has_edge(
        "arn:aws:iam::000000000000:role/role-a",
        "arn:aws:iam::000000000000:role/role-b",
    )
    assert not G.has_edge(
        "arn:aws:iam::000000000000:role/role-a",
        "arn:aws:iam::000000000000:role/role-a",
    )


def test_assume_role_edge_from_trust_policy():
    aws_data = _empty_aws_data()
    aws_data["roles"] = [
        {
            "Arn": "arn:aws:iam::000000000000:role/caller-role",
            "RoleName": "caller-role",
            "is_admin": False,
            "trust_principals": [],
            "passrole_resources": [],
        },
        {
            "Arn": "arn:aws:iam::000000000000:role/target-role",
            "RoleName": "target-role",
            "is_admin": True,
            "trust_principals": [
                {
                    "principal_type": "AWS",
                    "principal": "arn:aws:iam::000000000000:role/caller-role",
                    "action": "sts:AssumeRole",
                }
            ],
            "passrole_resources": [],
        },
    ]
    k8s_data = _empty_k8s_data()

    G = build_unified_graph(aws_data, k8s_data, [])

    assert G.has_edge(
        "arn:aws:iam::000000000000:role/caller-role",
        "arn:aws:iam::000000000000:role/target-role",
    )
    edge = G.edges[
        "arn:aws:iam::000000000000:role/caller-role",
        "arn:aws:iam::000000000000:role/target-role",
    ]
    assert edge["type"] == "sts:AssumeRole"


def test_group_membership_edge():
    aws_data = _empty_aws_data()
    aws_data["users"] = [
        {
            "Arn": "arn:aws:iam::000000000000:user/alice",
            "UserName": "alice",
            "is_admin": False,
            "group_arns": ["arn:aws:iam::000000000000:group/admins"],
            "passrole_resources": [],
        }
    ]
    aws_data["groups"] = [
        {
            "Arn": "arn:aws:iam::000000000000:group/admins",
            "GroupName": "admins",
            "is_admin": True,
        }
    ]
    k8s_data = _empty_k8s_data()

    G = build_unified_graph(aws_data, k8s_data, [])

    assert G.has_edge(
        "arn:aws:iam::000000000000:user/alice",
        "arn:aws:iam::000000000000:group/admins",
    )


def test_wildcard_trust_principal_does_not_create_edge():
    # Principal "*" means "anyone" -- not a specific node, should be skipped
    # (still a real misconfiguration, but not representable as one edge).
    aws_data = _empty_aws_data()
    aws_data["roles"] = [
        {
            "Arn": "arn:aws:iam::000000000000:role/open-role",
            "RoleName": "open-role",
            "is_admin": False,
            "trust_principals": [
                {"principal_type": "AWS", "principal": "*", "action": "sts:AssumeRole"}
            ],
            "passrole_resources": [],
        }
    ]
    k8s_data = _empty_k8s_data()

    G = build_unified_graph(aws_data, k8s_data, [])
    assert G.number_of_edges() == 0


def test_multiple_service_accounts_only_vulnerable_one_gets_irsa_edge():
    # Mirrors Benchmark 3: 5 SAs, only 1 has the IRSA bridge.
    aws_data = _empty_aws_data()
    aws_data["roles"] = [
        {
            "Arn": "arn:aws:iam::000000000000:role/admin-role",
            "RoleName": "admin-role",
            "is_admin": True,
            "trust_principals": [],
            "passrole_resources": [],
        }
    ]
    k8s_data = _empty_k8s_data()
    k8s_data["service_accounts"] = [_fake_sa(f"sa-{i}", "default") for i in range(5)]

    irsa_mappings = [
        {
            "service_account": "sa-2",
            "namespace": "default",
            "aws_role_arn": "arn:aws:iam::000000000000:role/admin-role",
        }
    ]

    G = build_unified_graph(aws_data, k8s_data, irsa_mappings)

    assert G.number_of_edges() == 1
    assert G.has_edge("k8s:sa:default:sa-2", "arn:aws:iam::000000000000:role/admin-role")
    for i in [0, 1, 3, 4]:
        assert not G.has_edge(
            f"k8s:sa:default:sa-{i}", "arn:aws:iam::000000000000:role/admin-role"
        )
