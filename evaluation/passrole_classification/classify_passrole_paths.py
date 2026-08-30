#!/usr/bin/env python3
"""
classify_passrole_paths.py -- two-tier classification of CrossGuard escalation
paths: Confirmed vs Conservative-Potential.

Context (why this exists): CrossGuard's L1 limitation is that it doesn't
evaluate policy Conditions. A path that reaches its target purely via an
iam:PassRole grant (no independently-modeled completing action, e.g. no
paired ec2:RunInstances/lambda:CreateFunction in the graph) is only a
REAL exploit if the target role's trust policy is broad enough (or
otherwise reachable) for the source identity to actually assume/use it.
If the target's trust policy is narrowly scoped to something like
ec2.amazonaws.com only, with no principal naming the source anywhere,
PassRole alone doesn't complete the escalation without a paired action
this tool doesn't model -- so the path is a real risk signal, but not a
confirmed, walk-through-able exploit chain.

This script re-derives edge types for every AWS-to-AWS hop in a path
(the exported --output-json doesn't carry edge types) by querying the
ACTUAL LocalStack trust policies and permission policies directly --
not by re-reading the graph, which only keeps one edge type per node
pair and would hide the redundancy check we need.

Classification rule, per hop (A -> B, both AWS IAM roles):
  - If B's trust policy explicitly lists A as an allowed Principal for
    sts:AssumeRole -> edge is "sts:AssumeRole", already a confirmed hop.
  - Else, if A has an iam:PassRole permission whose Resource covers B's
    ARN -> edge is "iam:PassRole". Then check for redundancy: does B's
    trust policy ALSO separately allow A (or a role A can reach) to
    assume it? If yes -> "passrole_backed" (confirmed, the AssumeRole
    edge already covers it independently). If no -> "passrole_bare"
    (conservative-potential: relies solely on PassRole with no modeled
    completing action).

A path's overall classification:
  - Confirmed: every hop is sts:AssumeRole or passrole_backed.
  - Conservative-Potential: at least one hop is passrole_bare.

Usage:
    python3 classify_passrole_paths.py --endpoint-url http://localhost:4566 \
        benchmark1_result.json benchmark2_result.json bench6_confirm_before.json \
        bench8_check.json bench9_result.json benchmark11_result.json ...

    # or glob everything in the current dir:
    python3 classify_passrole_paths.py --endpoint-url http://localhost:4566 \
        --glob "*_result.json" "bench*_check.json" "bench*_confirm_before.json"
"""

import argparse
import glob
import json
import sys

try:
    import boto3
except ImportError:
    sys.exit("boto3 required: pip install boto3 --break-system-packages")


ROLE_ARN_PREFIX = "arn:aws:iam::"


def is_role_arn(node_id: str) -> bool:
    return node_id.startswith(ROLE_ARN_PREFIX) and ":role/" in node_id


def role_name_from_arn(arn: str) -> str:
    return arn.rsplit("/", 1)[-1]


class IamCache:
    """Caches trust policies + PassRole-relevant inline/attached policy
    statements per role, so we don't re-fetch the same role for every
    path/hop that touches it."""

    def __init__(self, iam_client):
        self.iam = iam_client
        self._trust_cache = {}
        self._passrole_cache = {}

    def get_trust_principals(self, role_name: str):
        """Returns a set of AWS principal ARNs (or '*') explicitly allowed
        to sts:AssumeRole this role, from its trust policy."""
        if role_name in self._trust_cache:
            return self._trust_cache[role_name]
        principals = set()
        try:
            resp = self.iam.get_role(RoleName=role_name)
            doc = resp["Role"]["AssumeRolePolicyDocument"]
        except Exception as e:
            print(f"    [warn] could not fetch role {role_name}: {e}", file=sys.stderr)
            self._trust_cache[role_name] = principals
            return principals

        for stmt in doc.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            if "sts:AssumeRole" not in _as_list(stmt.get("Action", [])):
                continue
            principal = stmt.get("Principal", {})
            if principal == "*":
                principals.add("*")
                continue
            if isinstance(principal, dict):
                aws_principals = principal.get("AWS")
                if aws_principals:
                    principals.update(_as_list(aws_principals))
        self._trust_cache[role_name] = principals
        return principals

    def get_passrole_targets(self, role_name: str):
        """Returns a set of role ARNs (or '*') this role has iam:PassRole
        permission against, across all inline + attached-managed policies."""
        if role_name in self._passrole_cache:
            return self._passrole_cache[role_name]
        targets = set()

        # inline policies
        try:
            names = self.iam.list_role_policies(RoleName=role_name)["PolicyNames"]
        except Exception:
            names = []
        for pname in names:
            try:
                doc = self.iam.get_role_policy(RoleName=role_name, PolicyName=pname)[
                    "PolicyDocument"
                ]
            except Exception:
                continue
            targets |= _extract_passrole_resources(doc)

        # attached managed policies
        try:
            attached = self.iam.list_attached_role_policies(RoleName=role_name)[
                "AttachedPolicies"
            ]
        except Exception:
            attached = []
        for pol in attached:
            try:
                pol_arn = pol["PolicyArn"]
                ver_id = self.iam.get_policy(PolicyArn=pol_arn)["Policy"][
                    "DefaultVersionId"
                ]
                doc = self.iam.get_policy_version(
                    PolicyArn=pol_arn, VersionId=ver_id
                )["PolicyVersion"]["Document"]
            except Exception:
                continue
            targets |= _extract_passrole_resources(doc)

        self._passrole_cache[role_name] = targets
        return targets


def _as_list(x):
    return x if isinstance(x, list) else [x]


def _extract_passrole_resources(doc):
    out = set()
    for stmt in doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        if "iam:PassRole" not in _as_list(stmt.get("Action", [])):
            continue
        out |= set(_as_list(stmt.get("Resource", [])))
    return out


def principal_matches(principal_set, source_arn: str, source_name: str) -> bool:
    if "*" in principal_set:
        return True
    for p in principal_set:
        if p == source_arn or p.rsplit("/", 1)[-1] == source_name:
            return True
    return False


def resource_matches(resource_set, target_arn: str) -> bool:
    for r in resource_set:
        if r == "*" or r == target_arn:
            return True
    return False


def classify_hop(cache: IamCache, source_arn: str, target_arn: str):
    """Returns one of: 'sts:AssumeRole', 'passrole_backed', 'passrole_bare',
    'unresolved' (couldn't determine -- treated conservatively)."""
    source_name = role_name_from_arn(source_arn)
    target_name = role_name_from_arn(target_arn)

    target_trust = cache.get_trust_principals(target_name)
    if principal_matches(target_trust, source_arn, source_name):
        return "sts:AssumeRole"

    source_passrole = cache.get_passrole_targets(source_name)
    if resource_matches(source_passrole, target_arn):
        # PassRole grant exists; already confirmed above that target's
        # trust does NOT separately name source -> bare.
        return "passrole_bare"

    return "unresolved"


def classify_path(cache: IamCache, path_nodes):
    aws_hops = []
    for a, b in zip(path_nodes, path_nodes[1:]):
        if is_role_arn(a) and is_role_arn(b):
            aws_hops.append((a, b))

    hop_results = []
    for a, b in aws_hops:
        edge_type = classify_hop(cache, a, b)
        hop_results.append((a, b, edge_type))

    if any(t == "passrole_bare" for _, _, t in hop_results):
        verdict = "Conservative-Potential"
    elif any(t == "unresolved" for _, _, t in hop_results):
        verdict = "Conservative-Potential"  # unresolved treated conservatively
    else:
        verdict = "Confirmed"

    return verdict, hop_results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint-url", default="http://localhost:4566")
    ap.add_argument("--glob", nargs="*", default=[])
    ap.add_argument("files", nargs="*")
    args = ap.parse_args()

    files = list(args.files)
    for pattern in args.glob:
        files.extend(glob.glob(pattern))
    files = sorted(set(files))
    if not files:
        sys.exit("No input files given. Pass --output-json result files or --glob patterns.")

    iam = boto3.client(
        "iam",
        endpoint_url=args.endpoint_url,
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    cache = IamCache(iam)

    summary = {"Confirmed": 0, "Conservative-Potential": 0}
    per_benchmark = []

    for fpath in files:
        try:
            with open(fpath) as f:
                data = json.load(f)
        except Exception as e:
            print(f"[skip] {fpath}: {e}", file=sys.stderr)
            continue

        paths = data.get("paths", [])
        if not paths:
            continue

        print(f"\n=== {fpath} ===")
        for p in paths:
            nodes = p.get("path", [])
            verdict, hops = classify_path(cache, nodes)
            summary[verdict] = summary.get(verdict, 0) + 1
            per_benchmark.append((fpath, p.get("start"), p.get("end"), verdict))
            print(f"  {p.get('start')} -> {p.get('end')}  ==>  {verdict}")
            for a, b, t in hops:
                print(f"      {role_name_from_arn(a)} -> {role_name_from_arn(b)} : {t}")

    print("\n" + "=" * 55)
    print("SUMMARY (two-tier classification)")
    total = sum(summary.values())
    for k, v in summary.items():
        pct = (100 * v / total) if total else 0
        print(f"  {k}: {v}/{total} ({pct:.1f}%)")

    print("\nPer-path table:")
    print(f"{'File':45s} {'Start':35s} {'End':40s} {'Verdict'}")
    for fpath, start, end, verdict in per_benchmark:
        print(f"{fpath:45s} {str(start):35s} {str(end):40s} {verdict}")

    out = {
        "summary": summary,
        "paths": [
            {"file": f, "start": s, "end": e, "verdict": v}
            for f, s, e, v in per_benchmark
        ],
    }
    with open("passrole_classification_results.json", "w") as f:
        json.dump(out, f, indent=2)
    print("\nWritten: passrole_classification_results.json")


if __name__ == "__main__":
    main()
