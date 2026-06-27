"""
graph/builder.py

Builds the unified cross-layer privilege graph from AWS IAM data
(ingestion.aws_ingestion.ingest_aws) and Kubernetes RBAC data
(ingestion.k8s_ingestion.ingest_k8s), bridged by IRSA mappings
(ingestion.k8s_ingestion.find_irsa_mappings).

This is the core novel contribution (C1): a single NetworkX DiGraph
containing both AWS IAM and Kubernetes RBAC entities, connected via the
IRSA bridge edge (C2).
"""

from __future__ import annotations

import logging

import networkx as nx

logger = logging.getLogger(__name__)


def _sa_node_id(namespace: str, name: str) -> str:
    return f"k8s:sa:{namespace}:{name}"


def _role_node_id(namespace: str, name: str) -> str:
    return f"k8s:role:{namespace}:{name}"


def _cluster_role_node_id(name: str) -> str:
    return f"k8s:clusterrole:{name}"


def _add_aws_nodes(G, aws_data):
    for user in aws_data.get("users", []):
        G.add_node(
            user["Arn"],
            type="aws_user",
            name=user["UserName"],
            is_admin=user.get("is_admin", False),
        )

    for role in aws_data.get("roles", []):
        G.add_node(
            role["Arn"],
            type="aws_role",
            name=role["RoleName"],
            is_admin=role.get("is_admin", False),
        )

    for group in aws_data.get("groups", []):
        G.add_node(
            group["Arn"],
            type="aws_group",
            name=group["GroupName"],
            is_admin=group.get("is_admin", False),
        )


def _add_aws_assume_role_edges(G, aws_data):
    """Trust policy principals -> the role they can assume."""
    for role in aws_data.get("roles", []):
        role_arn = role["Arn"]
        for principal in role.get("trust_principals", []):
            if principal["principal_type"] != "AWS":
                continue  # Service/Federated principals aren't graph nodes
            principal_arn = principal["principal"]
            if principal_arn == "*":
                continue  # "anyone" -- not a specific node; a misconfiguration to flag separately
            if G.has_node(principal_arn):
                G.add_edge(
                    principal_arn, role_arn,
                    type="sts:AssumeRole",
                    label="can assume",
                )


def _add_passrole_edges(G, aws_data):
    """X has iam:PassRole on role R -> edge X -> R.
    A wildcard ("*") Resource means X can pass ANY role -- model that as
    an edge to every role in the graph, since that's the real-world risk."""
    all_role_arns = [r["Arn"] for r in aws_data.get("roles", [])]

    for entity_list in (aws_data.get("users", []), aws_data.get("roles", [])):
        for entity in entity_list:
            source_arn = entity["Arn"]
            for resource in entity.get("passrole_resources", []):
                targets = all_role_arns if resource == "*" else [resource]
                for target_arn in targets:
                    if target_arn == source_arn:
                        continue
                    if G.has_node(target_arn):
                        G.add_edge(
                            source_arn, target_arn,
                            type="iam:PassRole",
                            label="can pass role to",
                        )


def _add_group_membership_edges(G, aws_data):
    """User -> Group they belong to (inherits the group's permissions)."""
    for user in aws_data.get("users", []):
        user_arn = user["Arn"]
        for group_arn in user.get("group_arns", []):
            if G.has_node(group_arn):
                G.add_edge(
                    user_arn, group_arn,
                    type="group_membership",
                    label="member of",
                )


def _add_k8s_nodes(G, k8s_data):
    for sa in k8s_data.get("service_accounts", []):
        node_id = _sa_node_id(sa.metadata.namespace, sa.metadata.name)
        G.add_node(
            node_id,
            type="k8s_service_account",
            name=sa.metadata.name,
            namespace=sa.metadata.namespace,
        )

    for role in k8s_data.get("roles", []):
        node_id = _role_node_id(role.metadata.namespace, role.metadata.name)
        G.add_node(
            node_id,
            type="k8s_role",
            name=role.metadata.name,
            namespace=role.metadata.namespace,
        )

    for cr in k8s_data.get("cluster_roles", []):
        node_id = _cluster_role_node_id(cr.metadata.name)
        G.add_node(
            node_id,
            type="k8s_cluster_role",
            name=cr.metadata.name,
        )


def _add_rbac_binding_edges(G, k8s_data):
    """RoleBinding/ClusterRoleBinding subjects -> the Role/ClusterRole
    they're bound to. Only ServiceAccount subjects are modeled as nodes
    here (K8s Users/Groups aren't first-class objects in the cluster API
    the way ServiceAccounts are)."""
    for rb in k8s_data.get("role_bindings", []):
        role_ref = rb.role_ref
        if role_ref.kind == "Role":
            target = _role_node_id(rb.metadata.namespace, role_ref.name)
        else:  # a RoleBinding can also reference a ClusterRole
            target = _cluster_role_node_id(role_ref.name)

        if not G.has_node(target):
            continue

        for subject in (rb.subjects or []):
            if subject.kind != "ServiceAccount":
                continue
            subj_namespace = subject.namespace or rb.metadata.namespace
            subj_node = _sa_node_id(subj_namespace, subject.name)
            if G.has_node(subj_node):
                G.add_edge(subj_node, target, type="rbac_binding", label="bound to")

    for crb in k8s_data.get("cluster_role_bindings", []):
        target = _cluster_role_node_id(crb.role_ref.name)
        if not G.has_node(target):
            continue
        for subject in (crb.subjects or []):
            if subject.kind != "ServiceAccount":
                continue
            subj_node = _sa_node_id(subject.namespace, subject.name)
            if G.has_node(subj_node):
                G.add_edge(subj_node, target, type="rbac_binding", label="bound to")


def _add_irsa_edges(G, irsa_mappings):
    """The novel cross-layer bridge (C2): K8s ServiceAccount -> AWS Role."""
    for mapping in irsa_mappings:
        sa_node = _sa_node_id(mapping["namespace"], mapping["service_account"])
        aws_role_node = mapping["aws_role_arn"]
        if G.has_node(sa_node) and G.has_node(aws_role_node):
            G.add_edge(sa_node, aws_role_node, type="irsa_bridge", label="IRSA -> assumes")
        else:
            logger.warning(
                "IRSA mapping references missing node(s): sa=%s (exists=%s), role=%s (exists=%s)",
                sa_node, G.has_node(sa_node), aws_role_node, G.has_node(aws_role_node),
            )


def build_unified_graph(aws_data: dict, k8s_data: dict, irsa_mappings: list[dict]) -> nx.DiGraph:
    """Build the single cross-layer directed graph (C1).

    Args:
        aws_data: output of ingestion.aws_ingestion.ingest_aws()
        k8s_data: output of ingestion.k8s_ingestion.ingest_k8s()
        irsa_mappings: output of ingestion.k8s_ingestion.find_irsa_mappings()

    Returns:
        A networkx.DiGraph where nodes are AWS IAM / K8s RBAC entities and
        edges represent ways privilege can flow between them.
    """
    G = nx.DiGraph()

    _add_aws_nodes(G, aws_data)
    _add_k8s_nodes(G, k8s_data)

    _add_aws_assume_role_edges(G, aws_data)
    _add_passrole_edges(G, aws_data)
    _add_group_membership_edges(G, aws_data)
    _add_rbac_binding_edges(G, k8s_data)
    _add_irsa_edges(G, irsa_mappings)

    logger.info("Built unified graph: %d nodes, %d edges", G.number_of_nodes(), G.number_of_edges())
    return G
