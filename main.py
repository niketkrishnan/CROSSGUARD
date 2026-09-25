"""
main.py

Entry point for the Unified Cross-Layer Privilege Escalation Analysis
and Remediation Framework.

Usage:
    python main.py --endpoint-url http://localhost:4566
    python main.py --aws-profile myprofile
    python main.py --kube-config ~/.kube/config --endpoint-url http://localhost:4566
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import sys

from ingestion.aws_ingestion import ingest_aws
from ingestion.k8s_ingestion import find_irsa_mappings, ingest_k8s
from graph.builder import build_unified_graph
from pathfinder.search import annotate_path_confidence, describe_path, find_all_cross_layer_paths
from ingestion import policy_eval
from scoring.risk import score_all_paths
from remediation.engine import find_minimum_remediation

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Unified Cross-Layer Privilege Escalation Analysis and Remediation Framework"
    )
    parser.add_argument(
        "--aws-profile", default=None,
        help="Named AWS CLI profile to use (default: default credential chain)",
    )
    parser.add_argument(
        "--endpoint-url", default=None,
        help="AWS endpoint URL, e.g. http://localhost:4566 to target LocalStack instead of real AWS",
    )
    parser.add_argument(
        "--region", default="us-east-1",
        help="AWS region (default: us-east-1)",
    )
    parser.add_argument(
        "--kube-config", default=None,
        help="Path to kubeconfig file (default: ~/.kube/config)",
    )
    parser.add_argument(
        "--in-cluster", action="store_true",
        help="Use in-cluster K8s service account auth instead of a kubeconfig file",
    )
    parser.add_argument(
        "--semantics", choices=["strict", "annotate", "legacy"], default="strict",
        help="Policy evaluation mode. strict (default): Deny/Condition/PassRole-pairing/"
             "wildcard-trust, and drops edges that are definitely unusable (invalid IRSA "
             "trust, unassumable PassRole target); drops are logged. annotate: same "
             "checks but keeps every edge and only labels it. legacy: original "
             "presence-only behaviour.",
    )
    parser.add_argument(
        "--oidc-provider-arn", default=None,
        help="ARN of the cluster's IAM OIDC provider. If set, IRSA trust is only "
             "'valid' when the role trusts exactly this provider (otherwise any OIDC "
             "provider principal is accepted).",
    )
    parser.add_argument(
        "--output-json", default=None,
        help="Optional path to also write the full result as JSON",
    )
    return parser.parse_args()


def build_result(aws_data, k8s_data, irsa_mappings, G, paths, remediations, semantics) -> dict:
    """Single place that assembles the result dict, so the "no paths" and
    "paths found" branches cannot drift apart. The suppression log and the
    wildcard-trust exposure findings must be present even when there are no
    paths: that is exactly when they matter (e.g. every path was suppressed)."""
    return {
        "aws_summary": {
            "users": len(aws_data["users"]),
            "roles": len(aws_data["roles"]),
            "groups": len(aws_data["groups"]),
        },
        "k8s_summary": {
            "service_accounts": len(k8s_data["service_accounts"]),
            "roles": len(k8s_data["roles"]),
            "cluster_roles": len(k8s_data["cluster_roles"]),
        },
        "irsa_mappings": irsa_mappings,
        "graph_nodes": G.number_of_nodes(),
        "graph_edges": G.number_of_edges(),
        "paths": paths,
        "remediations": remediations,
        "semantics": semantics,
        "suppressed_edges": G.graph.get("suppressed_edges", []),
        "wildcard_trust_roles": G.graph.get("wildcard_trust_roles", []),
    }


def run(
    aws_profile: str | None = None,
    endpoint_url: str | None = None,
    region: str = "us-east-1",
    kube_config_path: str | None = None,
    in_cluster: bool = False,
    semantics: str = "strict",
    oidc_provider_arn: str | None = None,
) -> dict:
    """Run the full pipeline and return a structured result dict (so this
    function is also reusable from tests or a future API/UI, not just the
    CLI)."""
    print("[1] Ingesting AWS IAM config...")
    aws_data = ingest_aws(profile=aws_profile, endpoint_url=endpoint_url, region=region)
    print(f"    {len(aws_data['users'])} users, {len(aws_data['roles'])} roles, "
          f"{len(aws_data['groups'])} groups")

    print("[2] Ingesting Kubernetes RBAC config...")
    k8s_data = ingest_k8s(kube_config_path=kube_config_path, in_cluster=in_cluster)
    print(f"    {len(k8s_data['service_accounts'])} service accounts, "
          f"{len(k8s_data['roles'])} roles, {len(k8s_data['cluster_roles'])} cluster roles")

    print("[3] Finding IRSA mappings...")
    irsa_mappings = find_irsa_mappings(k8s_data["service_accounts"])
    print(f"    {len(irsa_mappings)} mapping(s) found")

    print("[4] Building unified privilege graph...")
    cfg = {"strict": policy_eval.STRICT, "annotate": policy_eval.ANNOTATE, "legacy": policy_eval.LEGACY}[semantics]
    if oidc_provider_arn:
        cfg = dataclasses.replace(cfg, oidc_provider_arn=oidc_provider_arn)
    G = build_unified_graph(aws_data, k8s_data, irsa_mappings, config=cfg)
    print(f"    Graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

    print("[5] Finding cross-layer escalation paths...")
    paths = annotate_path_confidence(G, find_all_cross_layer_paths(G))

    if not paths:
        print("\nNo cross-layer escalation paths found.")
        return build_result(aws_data, k8s_data, irsa_mappings, G, [], [], semantics)

    scored_paths = score_all_paths(G, paths)

    print(f"\n[!] Found {len(scored_paths)} cross-layer escalation path(s):\n")
    for i, path in enumerate(scored_paths):
        print(f"Path {i + 1} (Risk Score: {path['risk_score']}, confidence: {path.get('confidence')}):")
        print("  " + describe_path(G, path))
        print()

    print("[6] Computing minimal remediation...")
    remediations = find_minimum_remediation(G, scored_paths)

    print("\nRemediation recommendations:")
    for r in remediations:
        print(f"  - {r['action']}")
        if r.get("command"):
            print(f"    Command: {r['command']}")

    return build_result(aws_data, k8s_data, irsa_mappings, G, scored_paths, remediations, semantics)


def main() -> int:
    args = parse_args()
    try:
        result = run(
            aws_profile=args.aws_profile,
            endpoint_url=args.endpoint_url,
            region=args.region,
            kube_config_path=args.kube_config,
            in_cluster=args.in_cluster,
            semantics=args.semantics,
            oidc_provider_arn=args.oidc_provider_arn,
        )
    except Exception as e:  # noqa: BLE001
        print(f"\nERROR: {e}", file=sys.stderr)
        return 1

    if args.output_json:
        with open(args.output_json, "w") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"\nFull results written to {args.output_json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
