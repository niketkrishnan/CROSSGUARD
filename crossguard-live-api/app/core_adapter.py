"""
Bridge between the API and your real CrossGuard core modules.
Wired against actual signatures confirmed from the repo -- not guesses.
"""
from __future__ import annotations

import json

import networkx as nx
from kubernetes import client as k8s_client_lib
from kubernetes import config as k8s_config_lib

from graph.builder import build_unified_graph
from ingestion.aws_ingestion import ingest_aws
from ingestion.k8s_ingestion import find_irsa_mappings, ingest_k8s
from pathfinder.search import find_all_cross_layer_paths
from remediation.engine import find_minimum_remediation
from scoring.risk import score_all_paths

# The annotation IRSA relies on -- see ingestion/k8s_ingestion.py's
# find_irsa_mappings(), which is what CrossGuard scans FOR. Removing it
# is the actual fix: it's the same operation as
#   kubectl annotate serviceaccount <name> -n <namespace> eks.amazonaws.com/role-arn-
IRSA_ANNOTATION_KEY = "eks.amazonaws.com/role-arn"


def _parse_iam_arn(arn: str) -> tuple[str, str]:
    """arn:aws:iam::ACCOUNT:role/path/Name -> ('role', 'Name'). Handles
    paths (role/team/Name) by taking the last segment as the name."""
    resource = arn.split(":", 5)[5]
    parts = resource.split("/")
    return parts[0], parts[-1]


def run_aws_ingestion(iam_client) -> dict:
    return ingest_aws(iam_client=iam_client)


def run_k8s_ingestion(kube_config_path: str) -> dict:
    return ingest_k8s(kube_config_path=kube_config_path)


def build_graph(aws_data: dict, k8s_data: dict) -> nx.DiGraph:
    irsa_mappings = find_irsa_mappings(k8s_data["service_accounts"])
    return build_unified_graph(aws_data, k8s_data, irsa_mappings)


def find_paths(graph: nx.DiGraph) -> list[dict]:
    raw_paths = find_all_cross_layer_paths(graph)
    return score_all_paths(graph, raw_paths)


def compute_all_remediations(graph: nx.DiGraph, paths: list[dict]) -> list[dict]:
    """
    Global min-cut remediation -- one call for ALL paths at once (this is
    what makes the B6 "one fix closes two paths" result possible). Each
    returned dict has: action, edge_type, command, source, target.
    """
    return find_minimum_remediation(graph, paths)


def _remove_trust_policy_principal(iam_client, edge_cut: dict) -> None:
    """sts:AssumeRole fix: remove edge_cut['source'] (a principal ARN)
    from the trust policy of the role at edge_cut['target']. Only ever
    touches statements that actually list this principal -- drops the
    principal from a multi-principal statement, or drops the whole
    statement if this was its only principal. Never touches Service/
    Federated principal statements."""
    src, dst = edge_cut["source"], edge_cut["target"]
    _, role_name = _parse_iam_arn(dst)

    role = iam_client.get_role(RoleName=role_name)["Role"]
    trust_doc = role.get("AssumeRolePolicyDocument", {})
    stmts = trust_doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]

    new_stmts, changed = [], False
    for stmt in stmts:
        aws_principals = (stmt.get("Principal") or {}).get("AWS")
        aws_list = aws_principals if isinstance(aws_principals, list) else ([aws_principals] if aws_principals else [])
        if src not in aws_list:
            new_stmts.append(stmt)
            continue
        changed = True
        remaining = [p for p in aws_list if p != src]
        if not remaining:
            continue  # this principal was the only one -- drop the statement
        stmt = dict(stmt)
        stmt["Principal"] = {**stmt["Principal"], "AWS": remaining[0] if len(remaining) == 1 else remaining}
        new_stmts.append(stmt)

    if not changed:
        return  # already removed (idempotent retry) -- not an error

    if not new_stmts:
        # IAM rejects an empty Statement array (MalformedPolicyDocument).
        # Standard pattern for "make this role permanently unassumable"
        # without deleting it: point the trust policy at AWS's fixed
        # placeholder example account (123456789012), which will never
        # exist -- so nothing can ever actually satisfy this statement,
        # while the document stays syntactically valid.
        new_stmts = [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
            "Action": "sts:AssumeRole",
        }]

    new_doc = {**trust_doc, "Statement": new_stmts}
    iam_client.update_assume_role_policy(RoleName=role_name, PolicyDocument=json.dumps(new_doc))


def _remove_group_membership(iam_client, edge_cut: dict) -> None:
    """group_membership fix: single, safe, well-scoped API call."""
    src, dst = edge_cut["source"], edge_cut["target"]
    _, user_name = _parse_iam_arn(src)
    _, group_name = _parse_iam_arn(dst)
    iam_client.remove_user_from_group(UserName=user_name, GroupName=group_name)


def _remove_passrole_grant(iam_client, edge_cut: dict) -> None:
    """iam:PassRole fix. Only edits INLINE policies on the source entity
    -- never touches attached managed policies (those may be shared by
    other principals) and never auto-narrows a Resource:'*' grant
    (narrowing it correctly requires knowing every role this entity
    legitimately needs, which this tool can't infer safely). Both of
    those cases raise a clear error instead of guessing."""
    src, dst = edge_cut["source"], edge_cut["target"]
    entity_type, entity_name = _parse_iam_arn(src)

    if entity_type == "role":
        list_fn, get_fn, put_fn, delete_fn, kw = (
            iam_client.list_role_policies, iam_client.get_role_policy,
            iam_client.put_role_policy, iam_client.delete_role_policy, "RoleName",
        )
    elif entity_type == "user":
        list_fn, get_fn, put_fn, delete_fn, kw = (
            iam_client.list_user_policies, iam_client.get_user_policy,
            iam_client.put_user_policy, iam_client.delete_user_policy, "UserName",
        )
    else:
        raise NotImplementedError(f"PassRole removal not supported for entity type {entity_type!r}")

    inline_names = list_fn(**{kw: entity_name})["PolicyNames"]
    modified_any = False

    for policy_name in inline_names:
        doc = get_fn(**{kw: entity_name, "PolicyName": policy_name})["PolicyDocument"]
        stmts = doc.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]

        new_stmts, changed = [], False
        for stmt in stmts:
            if stmt.get("Effect") != "Allow":
                new_stmts.append(stmt)
                continue
            actions = stmt.get("Action", [])
            actions = actions if isinstance(actions, list) else [actions]
            if not any(a.lower() in ("iam:passrole", "iam:*", "*") for a in actions):
                new_stmts.append(stmt)
                continue

            resources = stmt.get("Resource", [])
            resources = resources if isinstance(resources, list) else [resources]

            if dst in resources:
                changed = True
                remaining = [r for r in resources if r != dst]
                if remaining:
                    stmt = dict(stmt)
                    stmt["Resource"] = remaining[0] if len(remaining) == 1 else remaining
                    new_stmts.append(stmt)
                # else: drop the statement entirely
            elif "*" in resources:
                raise RuntimeError(
                    f"Inline policy '{policy_name}' on {entity_name} grants iam:PassRole on "
                    f"Resource '*' -- refusing to auto-remove. This needs manual scoping down "
                    f"to the specific roles {entity_name} actually needs."
                )
            else:
                new_stmts.append(stmt)

        if changed:
            modified_any = True
            if new_stmts:
                put_fn(**{kw: entity_name, "PolicyName": policy_name, "PolicyDocument": json.dumps({**doc, "Statement": new_stmts})})
            else:
                delete_fn(**{kw: entity_name, "PolicyName": policy_name})

    if not modified_any:
        raise RuntimeError(
            f"Could not find an inline policy on {entity_name} granting iam:PassRole on {dst}. "
            f"It likely comes from an attached MANAGED policy, which is not auto-edited since "
            f"other principals may share it -- remove or replace that attachment manually."
        )


def apply_aws_edge_removal(iam_client, edge_cut: dict) -> None:
    edge_type = edge_cut["edge_type"]
    if edge_type == "sts:AssumeRole":
        _remove_trust_policy_principal(iam_client, edge_cut)
    elif edge_type == "group_membership":
        _remove_group_membership(iam_client, edge_cut)
    elif edge_type == "iam:PassRole":
        _remove_passrole_grant(iam_client, edge_cut)
    else:
        raise NotImplementedError(f"No AWS-side apply implemented for edge_type={edge_type!r}")


def apply_k8s_edge_removal(kube_config_path: str, edge_cut: dict) -> None:
    """
    Executes a K8s-side fix. Currently handles irsa_bridge: removes the
    eks.amazonaws.com/role-arn annotation from the ServiceAccount named
    in edge_cut["source"], which your graph builder ids as
    "k8s:sa:{namespace}:{name}" (see graph/builder.py _sa_node_id).

    Read-modify-write rather than a raw patch, so this only ever touches
    the one annotation key -- every other field on the ServiceAccount is
    round-tripped unchanged.
    """
    edge_type = edge_cut["edge_type"]
    if edge_type != "irsa_bridge":
        raise NotImplementedError(f"No K8s-side apply implemented yet for edge_type={edge_type!r}")

    source = edge_cut["source"]
    parts = source.split(":")
    if len(parts) != 4 or parts[0] != "k8s" or parts[1] != "sa":
        raise ValueError(f"Unexpected irsa_bridge source node id format: {source!r}")
    namespace, name = parts[2], parts[3]

    api_client = k8s_config_lib.new_client_from_config(config_file=kube_config_path)
    core_v1 = k8s_client_lib.CoreV1Api(api_client)

    sa = core_v1.read_namespaced_service_account(name=name, namespace=namespace)
    annotations = sa.metadata.annotations or {}
    if IRSA_ANNOTATION_KEY not in annotations:
        # Already removed (e.g. a retried apply) -- nothing to do, not an error.
        return
    del annotations[IRSA_ANNOTATION_KEY]
    sa.metadata.annotations = annotations
    core_v1.replace_namespaced_service_account(name=name, namespace=namespace, body=sa)


# Edge types whose fix requires the Kubernetes API rather than AWS IAM.
K8S_SIDE_EDGE_TYPES = {"irsa_bridge"}
