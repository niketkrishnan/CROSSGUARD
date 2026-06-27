"""
ingestion/k8s_ingestion.py

Pulls Kubernetes RBAC configuration via the official kubernetes Python
client, plus detects the IRSA bridge annotation that links a K8s
ServiceAccount to an AWS IAM role -- this is the cross-layer edge (C2)
that no existing tool models.
"""

from __future__ import annotations

import logging

from kubernetes import client, config

logger = logging.getLogger(__name__)

IRSA_ANNOTATION_KEY = "eks.amazonaws.com/role-arn"


def _load_config(kube_config_path: str | None, in_cluster: bool) -> None:
    if in_cluster:
        config.load_incluster_config()
    else:
        # kube_config_path=None means "use the default ~/.kube/config"
        config.load_kube_config(config_file=kube_config_path)


def ingest_k8s(
    kube_config_path: str | None = None,
    in_cluster: bool = False,
) -> dict:
    """Pull all RBAC entities needed for the unified graph.

    Args:
        kube_config_path: path to a kubeconfig file. None uses the default
            (~/.kube/config), which is what Minikube writes to.
        in_cluster: set True only when this code itself runs as a pod
            inside the cluster being analyzed (uses the in-cluster
            service account token instead of a kubeconfig file).

    Returns:
        {
          "service_accounts": [...],
          "roles": [...],
          "role_bindings": [...],
          "cluster_roles": [...],
          "cluster_role_bindings": [...],
        }
        Items are the raw kubernetes-client model objects (e.g.
        V1ServiceAccount) -- the graph builder reads attributes like
        .metadata.name directly off these.
    """
    _load_config(kube_config_path, in_cluster)

    core_v1 = client.CoreV1Api()
    rbac_v1 = client.RbacAuthorizationV1Api()

    logger.info("Listing service accounts across all namespaces...")
    service_accounts = core_v1.list_service_account_for_all_namespaces().items

    logger.info("Listing RBAC Roles/RoleBindings/ClusterRoles/ClusterRoleBindings...")
    roles = rbac_v1.list_role_for_all_namespaces().items
    role_bindings = rbac_v1.list_role_binding_for_all_namespaces().items
    cluster_roles = rbac_v1.list_cluster_role().items
    cluster_role_bindings = rbac_v1.list_cluster_role_binding().items

    return {
        "service_accounts": service_accounts,
        "roles": roles,
        "role_bindings": role_bindings,
        "cluster_roles": cluster_roles,
        "cluster_role_bindings": cluster_role_bindings,
    }


def find_irsa_mappings(service_accounts: list) -> list[dict]:
    """Scan ServiceAccounts for the IRSA annotation and return the
    cross-layer bridge mappings.

    IRSA annotation looks like:
        eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/MyRole

    Returns:
        [{"service_account": "vulnerable-sa", "namespace": "default",
          "aws_role_arn": "arn:aws:iam::000000000000:role/admin-role"}, ...]
    """
    mappings: list[dict] = []
    for sa in service_accounts:
        annotations = sa.metadata.annotations or {}
        role_arn = annotations.get(IRSA_ANNOTATION_KEY)
        if not role_arn:
            continue
        mappings.append(
            {
                "service_account": sa.metadata.name,
                "namespace": sa.metadata.namespace,
                "aws_role_arn": role_arn,
            }
        )
    if mappings:
        logger.info("Found %d IRSA bridge mapping(s)", len(mappings))
    return mappings


def find_pods_for_service_account(core_v1, service_account_name: str, namespace: str) -> list:
    """Find pods running under a given ServiceAccount. Useful for the
    pathfinder later to report "Pod X is the entry point" rather than just
    naming the bare ServiceAccount (Benchmark 3 in the eval plan needs this:
    5 pods, only 1 has the IRSA-annotated SA -- we want to name that pod)."""
    pods = core_v1.list_namespaced_pod(namespace=namespace).items
    return [p for p in pods if p.spec.service_account_name == service_account_name]
