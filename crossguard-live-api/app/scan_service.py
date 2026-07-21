"""
Orchestrates one scan: assume role -> ingest AWS + K8s -> build graph ->
find + score paths -> compute the global remediation set -> match each
remediation back to the paths it closes -> store results.

Runs as a FastAPI BackgroundTask so POST /scans returns immediately;
the frontend polls GET /scans/{id} for status.
"""
from __future__ import annotations

import logging
import secrets
import tempfile
from datetime import datetime, timezone

import networkx as nx
import yaml

from app import core_adapter, store
from app.aws_auth import AssumeRoleError, assume_role
from app.models import EscalationPath, GraphEdge, GraphNode, RemediationStatus, ScanRequest, ScanStatus

logger = logging.getLogger("crossguard_live.scan_service")


class InvalidKubeconfigError(Exception):
    pass


def _validate_kubeconfig_yaml(raw: str) -> None:
    """
    Catches malformed kubeconfig input with a clear message before it
    reaches the kubernetes client's config loader, whose internal errors
    for bad input (e.g. a plain string instead of a YAML mapping) are
    Python internals like "'str' object does not support item
    assignment" -- accurate to what went wrong internally, but useless
    to someone who just pasted the wrong thing.
    """
    try:
        parsed = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise InvalidKubeconfigError(f"Kubeconfig is not valid YAML: {exc}") from exc

    if not isinstance(parsed, dict):
        got = "empty content" if parsed is None else f"a {type(parsed).__name__}, not a mapping"
        raise InvalidKubeconfigError(
            f"Kubeconfig doesn't look like a valid kubeconfig file -- got {got}. "
            f"Expected a YAML document with 'clusters', 'contexts', and 'users' sections."
        )

    missing = [k for k in ("clusters", "contexts", "users") if k not in parsed]
    if missing:
        raise InvalidKubeconfigError(f"Kubeconfig is missing required section(s): {', '.join(missing)}.")


def _now():
    return datetime.now(timezone.utc)


def _serialize_graph(graph: nx.DiGraph, on_path_nodes: set[str], on_path_edges: set[tuple[str, str]]):
    nodes = []
    for node_id, data in graph.nodes(data=True):
        node_type = data.get("type", "unknown")
        layer = "aws" if node_type.startswith("aws_") else "k8s"
        nodes.append(
            GraphNode(
                id=str(node_id),
                label=data.get("name", str(node_id)),
                layer=layer,
                node_type=node_type,
                is_admin=bool(data.get("is_admin", False)),
                on_vulnerable_path=str(node_id) in on_path_nodes,
            ).model_dump()
        )
    edges = []
    for u, v, data in graph.edges(data=True):
        edges.append(
            GraphEdge(
                source=str(u),
                target=str(v),
                edge_type=data.get("type", "unknown"),
                on_vulnerable_path=(str(u), str(v)) in on_path_edges,
            ).model_dump()
        )
    return nodes, edges


def run_scan(scan_id: str, req: ScanRequest) -> None:
    store.update_scan(scan_id, status=ScanStatus.running)

    # Non-secret role config only -- needed so a later "apply remediation"
    # call can re-assume the role. Never store credentials themselves.
    store.save_aws_target(
        scan_id,
        {
            "role_arn": req.aws_target.role_arn,
            "region": req.aws_target.region,
            "external_id": req.aws_target.external_id,
            "endpoint_url_override": req.aws_target.endpoint_url_override,
        },
    )

    try:
        # --- AWS side ---
        creds = assume_role(
            role_arn=req.aws_target.role_arn,
            region=req.aws_target.region,
            external_id=req.aws_target.external_id,
            endpoint_url_override=req.aws_target.endpoint_url_override,
        )
        iam_client = creds.boto3_client("iam")
        aws_data = core_adapter.run_aws_ingestion(iam_client)

        # --- K8s side: validate first for a clean error, then ingest ---
        _validate_kubeconfig_yaml(req.k8s_target.kubeconfig_yaml)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=True) as tf:
            tf.write(req.k8s_target.kubeconfig_yaml)
            tf.flush()
            k8s_data = core_adapter.run_k8s_ingestion(tf.name)

        # --- Graph + pathfinding + risk scoring ---
        graph = core_adapter.build_graph(aws_data, k8s_data)
        scored_paths = core_adapter.find_paths(graph)  # each has: start, end, path, hops, cross_layer, risk_score

        # --- Global remediation set (may close >1 path per fix, e.g. B6) ---
        remediations = core_adapter.compute_all_remediations(graph, scored_paths)

        escalation_paths: list[EscalationPath] = []
        on_path_nodes: set[str] = set()
        on_path_edges: set[tuple[str, str]] = set()

        for raw in scored_paths:
            path_id = secrets.token_hex(6)
            node_seq = [str(n) for n in raw["path"]]

            on_path_nodes.update(node_seq)
            path_edges = list(zip(node_seq, node_seq[1:]))
            on_path_edges.update(path_edges)

            # Find the remediation (if any) whose cut edge lies on this path.
            matched = next(
                (r for r in remediations if (r.get("source"), r.get("target")) in path_edges),
                None,
            )

            escalation_paths.append(
                EscalationPath(
                    path_id=path_id,
                    scan_id=scan_id,
                    entry_node=node_seq[0],
                    target_node=node_seq[-1],
                    node_sequence=node_seq,
                    hop_count=raw["hops"],
                    risk_score=raw.get("risk_score", 0.0),
                    cross_layer=raw.get("cross_layer", False),
                    remediation_summary=matched["action"] if matched else None,
                    remediation_commands=[matched["command"]] if matched else [],
                    remediation_edge_cut=(
                        {"source": matched["source"], "target": matched["target"], "edge_type": matched["edge_type"]}
                        if matched
                        else None
                    ),
                    status=RemediationStatus.not_applied,
                )
            )

        nodes, edges = _serialize_graph(graph, on_path_nodes, on_path_edges)
        store.save_graph(scan_id, nodes, edges)
        store.save_paths(scan_id, escalation_paths)

        store.update_scan(
            scan_id,
            status=ScanStatus.completed,
            completed_at=_now(),
            node_count=len(nodes),
            edge_count=len(edges),
            path_count=len(escalation_paths),
        )

    except AssumeRoleError as exc:
        logger.warning("Scan %s failed at AssumeRole: %s", scan_id, exc)
        store.update_scan(scan_id, status=ScanStatus.failed, completed_at=_now(), error=str(exc))
    except Exception as exc:  # noqa: BLE001 -- surface every failure mode to the UI
        logger.exception("Scan %s failed", scan_id)
        store.update_scan(scan_id, status=ScanStatus.failed, completed_at=_now(), error=str(exc))
