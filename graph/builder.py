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

from ingestion import policy_eval as pe
from ingestion.policy_eval import (
    CONF_CONFIRMED, CONF_POTENTIAL, CONF_RANK, CONF_UNRESOLVED, EvalConfig,
)

logger = logging.getLogger(__name__)


def _suppress(G, source, target, etype, reason):
    """Record an edge the evaluator removed, so every suppression is auditable."""
    G.graph.setdefault("suppressed_edges", []).append(
        {"source": source, "target": target, "type": etype, "reason": reason}
    )


def _add_edge(G, u, v, etype, confidence=CONF_CONFIRMED, **attrs):
    """Add an edge, merging parallel mechanisms between the same node pair.

    networkx.DiGraph keeps ONE edge per (u, v). The original builder let a
    later edge type silently overwrite an earlier one (e.g. PassRole over
    AssumeRole), which hid a mechanism: cutting only the displayed type
    would not sever the connection. We keep the legacy `type` (last added
    wins, so scoring is unchanged) but record every mechanism in
    `edge_types` and its confidence in `type_confidence`.
    """
    if G.has_edge(u, v):
        d = G.edges[u, v]
        types = set(d.get("edge_types", [d.get("type")]))
        types.add(etype)
        d["edge_types"] = sorted(t for t in types if t)
        d.setdefault("type_confidence", {d.get("type"): d.get("confidence", CONF_CONFIRMED)})
        d["type_confidence"][etype] = confidence
        d["confidence"] = max(d["type_confidence"].values(), key=lambda c: CONF_RANK[c])
        d["type"] = etype
        d.update(attrs)
    else:
        G.add_edge(u, v, type=etype, edge_types=[etype], confidence=confidence,
                   type_confidence={etype: confidence}, **attrs)


def _sa_node_id(namespace: str, name: str) -> str:
    return f"k8s:sa:{namespace}:{name}"


def _role_node_id(namespace: str, name: str) -> str:
    return f"k8s:role:{namespace}:{name}"


def _cluster_role_node_id(name: str) -> str:
    return f"k8s:clusterrole:{name}"


def _admin_attrs(entity, cfg):
    st = pe.admin_status(entity, cfg)
    return {
        "is_admin": st["is_admin"],
        "is_admin_legacy": bool(entity.get("is_admin", False)),
        "admin_status": st["status"],
        "admin_partial_denies": st["partial_denies"],
        "admin_confidence": CONF_UNRESOLVED if st["status"] == "unresolved" else CONF_CONFIRMED,
    }


def _add_aws_nodes(G, aws_data, cfg):
    for user in aws_data.get("users", []):
        G.add_node(user["Arn"], type="aws_user", name=user["UserName"],
                   **_admin_attrs(user, cfg))

    for role in aws_data.get("roles", []):
        G.add_node(role["Arn"], type="aws_role", name=role["RoleName"],
                   **_admin_attrs(role, cfg))

    for group in aws_data.get("groups", []):
        G.add_node(group["Arn"], type="aws_group", name=group["GroupName"],
                   **_admin_attrs(group, cfg))


def _roles_by_arn(aws_data):
    return {r["Arn"]: r for r in aws_data.get("roles", [])}


def _add_aws_assume_role_edges(G, aws_data, cfg):
    """Trust policy principals -> the role they can assume.

    Wildcard trust (Principal:"*") used to be skipped entirely (L7). With
    cfg.wildcard_trust it is recorded on the role node, listed in
    G.graph["wildcard_trust_roles"], and turned into AssumeRole edges from
    every AWS identity whose own policy allows sts:AssumeRole on that role.
    """
    all_entities = list(aws_data.get("users", [])) + list(aws_data.get("roles", []))
    for role in aws_data.get("roles", []):
        role_arn = role["Arn"]
        trust_doc = role.get("AssumeRolePolicyDocument")

        if cfg.conditions and trust_doc:
            for item in pe.named_principal_trust(trust_doc, cfg):
                principal_arn = item["principal"]
                if not G.has_node(principal_arn):
                    continue
                conf = CONF_CONFIRMED if item["condition"] == pe.TRUE else CONF_UNRESOLVED
                _add_edge(G, principal_arn, role_arn, "sts:AssumeRole", conf,
                          label="can assume")
        else:
            for principal in role.get("trust_principals", []):
                if principal["principal_type"] != "AWS":
                    continue  # Service/Federated principals aren't graph nodes
                principal_arn = principal["principal"]
                if principal_arn == "*":
                    continue
                if G.has_node(principal_arn):
                    _add_edge(G, principal_arn, role_arn, "sts:AssumeRole",
                              CONF_CONFIRMED, label="can assume")

        if cfg.wildcard_trust and trust_doc:
            wstatus = pe.wildcard_trust_status(trust_doc)
            if wstatus:
                G.nodes[role_arn]["wildcard_trust"] = wstatus
                G.graph.setdefault("wildcard_trust_roles", []).append({
                    "role": role_arn, "status": wstatus,
                    "is_admin": G.nodes[role_arn].get("is_admin", False),
                })
                for ent in all_entities:
                    src = ent["Arn"]
                    if src == role_arn:
                        continue
                    stmts = pe.entity_statements(ent)
                    if not stmts:
                        continue
                    d = pe.decide(stmts, "sts:AssumeRole", role_arn, {})
                    if d == "deny":
                        _suppress(G, src, role_arn, "sts:AssumeRole", "explicit Deny on sts:AssumeRole")
                        continue
                    if d in ("allow", "allow_unresolved"):
                        conf = (CONF_CONFIRMED if (d == "allow" and wstatus == "unrestricted")
                                else CONF_UNRESOLVED)
                        _add_edge(G, src, role_arn, "sts:AssumeRole", conf,
                                  label="can assume (wildcard trust)", via="wildcard_trust")


def _legacy_passrole_edges(G, aws_data, entity, all_role_arns):
    source_arn = entity["Arn"]
    for resource in entity.get("passrole_resources", []):
        targets = all_role_arns if resource == "*" else [resource]
        for target_arn in targets:
            if target_arn == source_arn:
                continue
            if G.has_node(target_arn):
                _add_edge(G, source_arn, target_arn, "iam:PassRole", CONF_POTENTIAL,
                          label="can pass role to")


def _add_passrole_edges(G, aws_data, cfg):
    """X may iam:PassRole on role R -> edge X -> R.

    With raw policy documents available the grant is evaluated per target
    role (so Resource globs such as arn:...:role/app-* are honoured, which
    the original literal-or-"*" logic missed), Deny is applied, the
    PassedToService condition is checked against services the target
    actually trusts, and the paired-action check sets edge confidence.
    Entities without raw documents fall back to the legacy
    passrole_resources behaviour.
    """
    roles = _roles_by_arn(aws_data)
    all_role_arns = list(roles)
    for entity_list in (aws_data.get("users", []), aws_data.get("roles", [])):
        for entity in entity_list:
            source_arn = entity["Arn"]
            stmts = pe.entity_statements(entity)
            if not (cfg.conditions or cfg.deny) or not stmts:
                _legacy_passrole_edges(G, aws_data, entity, all_role_arns)
                continue
            # cheap pre-filter: does any statement mention PassRole at all?
            if not any(pe._action_hit(s, "iam:PassRole") for s in stmts):
                continue
            for target_arn, target in roles.items():
                if target_arn == source_arn or not G.has_node(target_arn):
                    continue
                res = pe.passrole_analysis(stmts, target_arn,
                                           target.get("AssumeRolePolicyDocument"), cfg)
                if res["decision"] in ("deny", "implicit_deny"):
                    if res["decision"] == "deny":
                        _suppress(G, source_arn, target_arn, "iam:PassRole", res["reason"])
                    continue
                conf = res["confidence"]
                if res.get("target_assumable_by_service") is False:
                    if cfg.passrole_target_trust == "strict":
                        _suppress(G, source_arn, target_arn, "iam:PassRole", res["reason"])
                        continue
                    if cfg.passrole_target_trust == "off":
                        pass
                _add_edge(G, source_arn, target_arn, "iam:PassRole", conf,
                          label="can pass role to",
                          passrole_reason=res["reason"],
                          passrole_services=res.get("services", []))


def _add_group_membership_edges(G, aws_data):
    """User -> Group they belong to (inherits the group's permissions)."""
    for user in aws_data.get("users", []):
        user_arn = user["Arn"]
        for group_arn in user.get("group_arns", []):
            if G.has_node(group_arn):
                _add_edge(G, user_arn, group_arn, "group_membership", CONF_CONFIRMED,
                          label="member of")


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
                _add_edge(G, subj_node, target, "rbac_binding", CONF_CONFIRMED, label="bound to")

    for crb in k8s_data.get("cluster_role_bindings", []):
        target = _cluster_role_node_id(crb.role_ref.name)
        if not G.has_node(target):
            continue
        for subject in (crb.subjects or []):
            if subject.kind != "ServiceAccount":
                continue
            subj_node = _sa_node_id(subject.namespace, subject.name)
            if G.has_node(subj_node):
                _add_edge(G, subj_node, target, "rbac_binding", CONF_CONFIRMED, label="bound to")


def _add_irsa_edges(G, irsa_mappings, aws_data, cfg):
    """The cross-layer bridge (C2): K8s ServiceAccount -> AWS Role.

    The edge is created from the annotation, as before. In addition the
    role's trust policy is now checked for whether it permits this
    ServiceAccount to assume it via web identity (sub/aud/MFA). Modes:
      off      -- legacy: no trust check, edge always confident
      annotate -- edge kept; `trust_status` recorded; only `valid` is
                  'confirmed', everything else is 'unresolved'
      strict   -- `invalid` trust suppresses the edge (logged in
                  G.graph["suppressed_edges"])
    """
    roles = _roles_by_arn(aws_data)
    for mapping in irsa_mappings:
        sa_node = _sa_node_id(mapping["namespace"], mapping["service_account"])
        aws_role_node = mapping["aws_role_arn"]
        if not (G.has_node(sa_node) and G.has_node(aws_role_node)):
            logger.warning(
                "IRSA mapping references missing node(s): sa=%s (exists=%s), role=%s (exists=%s)",
                sa_node, G.has_node(sa_node), aws_role_node, G.has_node(aws_role_node),
            )
            continue
        status, reason, conf = "not_evaluated", "IRSA trust check off", CONF_CONFIRMED
        if cfg.irsa_trust != "off":
            trust_doc = roles.get(aws_role_node, {}).get("AssumeRolePolicyDocument")
            status, reason = pe.irsa_trust_status(
                trust_doc, mapping["namespace"], mapping["service_account"], cfg)
            if status == "invalid" and cfg.irsa_trust == "strict":
                _suppress(G, sa_node, aws_role_node, "irsa_bridge", reason)
                continue
            if status == "valid":
                conf = CONF_CONFIRMED
            elif status == "not_evaluated":
                conf = CONF_CONFIRMED
            else:
                conf = CONF_UNRESOLVED
        _add_edge(G, sa_node, aws_role_node, "irsa_bridge", conf,
                  label="IRSA -> assumes", trust_status=status, trust_reason=reason)


def build_unified_graph(aws_data: dict, k8s_data: dict, irsa_mappings: list[dict],
                        config: EvalConfig | None = None) -> nx.DiGraph:
    """Build the single cross-layer directed graph (C1).

    Args:
        aws_data: output of ingestion.aws_ingestion.ingest_aws()
        k8s_data: output of ingestion.k8s_ingestion.ingest_k8s()
        irsa_mappings: output of ingestion.k8s_ingestion.find_irsa_mappings()
        config: evaluation switches (ingestion.policy_eval.EvalConfig). None
            means the default (strict) evaluator; pass policy_eval.LEGACY to reproduce
            the original behaviour exactly.

    Returns:
        A networkx.DiGraph where nodes are AWS IAM / K8s RBAC entities and
        edges represent ways privilege can flow between them. Edges carry a
        `confidence` (confirmed / potential / unresolved); suppressed edges
        are listed in G.graph["suppressed_edges"].
    """
    cfg = config or pe.DEFAULT
    G = nx.DiGraph()
    G.graph["eval_config"] = cfg.as_dict()

    _add_aws_nodes(G, aws_data, cfg)
    _add_k8s_nodes(G, k8s_data)

    _add_aws_assume_role_edges(G, aws_data, cfg)
    _add_passrole_edges(G, aws_data, cfg)
    _add_group_membership_edges(G, aws_data)
    _add_rbac_binding_edges(G, k8s_data)
    _add_irsa_edges(G, irsa_mappings, aws_data, cfg)

    logger.info("Built unified graph: %d nodes, %d edges", G.number_of_nodes(), G.number_of_edges())
    return G
