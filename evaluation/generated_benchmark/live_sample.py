"""
evaluation/generated_benchmark/live_sample.py

Selects a small, stratified sample of generated cases (default: 2 per
recipe, ~40 total) and writes them as a shell script that recreates each
case's AWS roles and Kubernetes ServiceAccount live in LocalStack + Minikube,
then runs main.py, so the offline evaluation (run_benchmark.py, in-memory
graph only) is checked against the real ingestion path at least once per
recipe. This is a SAMPLE, not full live coverage of all 4,000+8,000 cases --
that would take hours of LocalStack churn for no extra evidence beyond what
the offline harness plus this sample already show, since ingestion.aws_ingestion
and ingestion.k8s_ingestion are unit-tested separately and are not touched by
the recipes (they only vary policy content, which ingestion passes through
verbatim).

Usage:
    python -m evaluation.generated_benchmark.live_sample --split dev --per-recipe 2 \
        > evaluation/generated_benchmark/live_sample.sh
    bash evaluation/generated_benchmark/live_sample.sh
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from collections import defaultdict

ACCOUNT = "000000000000"


def _tag(case_id):
    """Short, unique, IAM-role-name-safe prefix so role names from different
    cases never collide when many cases are loaded into one AWS account."""
    return "g" + hashlib.sha1(case_id.encode()).hexdigest()[:10]


def namespace_case(case):
    """Return a deep copy of `case` with every AWS role name prefixed by a
    tag unique to this case, so live_sample.sh can load dozens of cases into
    one LocalStack account without name collisions. Rewrites RoleName, Arn,
    every ARN string embedded in policy documents (trust and inline), the
    sa_role_map values, and truth['target']. The original *_cases.jsonl files
    (used by run_benchmark.py, which builds one fresh in-memory graph per
    case and never collides) are left untouched."""
    c = copy.deepcopy(case)
    tag = _tag(c["case_id"])
    old_to_new_name = {r["RoleName"]: f"{tag}-{r['RoleName']}"[:64] for r in c["roles"]}
    old_to_new_arn = {f"arn:aws:iam::{ACCOUNT}:role/{old}": f"arn:aws:iam::{ACCOUNT}:role/{new}"
                      for old, new in old_to_new_name.items()}

    # A Resource glob such as "role/app-12345-*" shares only a PREFIX with a
    # role name ("app-12345-admin"), not the full name, so the exact-ARN
    # substitution above never touches it -- it stays stale after renaming
    # and no longer matches the (now tag-prefixed) target role. Every role
    # in one case gets the SAME tag, so inserting the tag right after
    # "role/" in any glob keeps the prefix relationship intact: a glob that
    # matched an old role name will match that role's new name too.
    glob_re = re.compile(rf"role/([A-Za-z0-9\-_.]*\*)")

    def _tag_glob(m):
        return f"role/{tag}-{m.group(1)}"

    def rewrite(obj):
        if isinstance(obj, str):
            for old_arn, new_arn in old_to_new_arn.items():
                if old_arn in obj:
                    obj = obj.replace(old_arn, new_arn)
            obj = glob_re.sub(_tag_glob, obj)
            return obj
        if isinstance(obj, list):
            return [rewrite(x) for x in obj]
        if isinstance(obj, dict):
            return {k: rewrite(v) for k, v in obj.items()}
        return obj

    for r in c["roles"]:
        r["RoleName"] = old_to_new_name[r["RoleName"]]
        r["Arn"] = f"arn:aws:iam::{ACCOUNT}:role/{r['RoleName']}"
        r["AssumeRolePolicyDocument"] = rewrite(r["AssumeRolePolicyDocument"])
        r["policy_documents"] = rewrite(r["policy_documents"])

    c["sa_role_map"] = {sa: old_to_new_name[role_name] for sa, role_name in c["sa_role_map"].items()}
    if c["truth"].get("target"):
        c["truth"]["target"] = old_to_new_arn.get(c["truth"]["target"], c["truth"]["target"])
    return c


def _versioned(doc):
    """AWS (and LocalStack, faithfully) rejects a policy document with no
    top-level Version. Offline (graph.builder/policy_eval) never checks it,
    so the generator omits it; add it only here, for the live path."""
    return {"Version": "2012-10-17", **doc}


def iam_role_cli(role):
    trust = json.dumps(_versioned(role["AssumeRolePolicyDocument"]))
    lines = [f"awslocal iam create-role --role-name {role['RoleName']} "
            f"--assume-role-policy-document '{trust}' >/dev/null"]
    for i, doc in enumerate(role.get("policy_documents", [])):
        pol = json.dumps(_versioned(doc))
        lines.append(f"awslocal iam put-role-policy --role-name {role['RoleName']} "
                    f"--policy-name inline-{i} --policy-document '{pol}' >/dev/null")
    if role.get("is_admin"):
        lines.append(f"awslocal iam attach-role-policy --role-name {role['RoleName']} "
                     f"--policy-arn arn:aws:iam::aws:policy/AdministratorAccess >/dev/null")
    return lines


def case_script(case):
    case = namespace_case(case)
    lines = [f'echo "=== {case["case_id"]} ({case["category"]}/{case["recipe"]}) ==="',
            "bash benchmarks/reset_environment.sh >/dev/null 2>&1"]
    for role in case["roles"]:
        lines += iam_role_cli(role)
    if case["sa_role_map"] and case["entry_ns"] != "default":
        lines.append(f"kubectl create namespace {case['entry_ns']} "
                     f"--dry-run=client -o yaml | kubectl apply -f - >/dev/null")
    for sa, role_name in case["sa_role_map"].items():
        lines.append(f"kubectl create serviceaccount {sa} -n {case['entry_ns']} "
                     f"--dry-run=client -o yaml | kubectl apply -f - >/dev/null")
        lines.append(f"kubectl annotate serviceaccount {sa} -n {case['entry_ns']} "
                     f"eks.amazonaws.com/role-arn=arn:aws:iam::000000000000:role/{role_name} "
                     f"--overwrite >/dev/null")
    out_json = f"evaluation/generated_benchmark/live/{case['case_id']}.json"
    lines.append(f"python main.py --endpoint-url http://localhost:4566 --semantics strict "
                f"--output-json {out_json} > evaluation/generated_benchmark/live/{case['case_id']}.log 2>&1")
    target = case["truth"].get("target")
    declared = case["truth"]["reachable"]
    entry_node = f"k8s:sa:{case['entry_ns']}:{case['entry_sa']}"
    lines.append(f"python -m evaluation.generated_benchmark.check_live_case "
                f"{out_json} '{target}' {declared} '{case['case_id']}' '{entry_node}'")
    return lines


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", choices=["dev", "heldout"], default="dev")
    ap.add_argument("--per-recipe", type=int, default=2)
    args = ap.parse_args()
    here = __file__.rsplit("/", 1)[0]
    by_recipe = defaultdict(list)
    for line in open(f"{here}/{args.split}_cases.jsonl"):
        c = json.loads(line)
        by_recipe[c["recipe"]].append(c)

    picked = []
    for recipe, cases in sorted(by_recipe.items()):
        picked.extend(cases[: args.per_recipe])

    print("#!/bin/bash")
    print("# Auto-generated by live_sample.py -- DO NOT EDIT BY HAND.")
    print(f"# {len(picked)} cases, {args.per_recipe} per recipe, split={args.split}")
    print("# Each case resets LocalStack (wipes IAM) before it runs, so cases never")
    print("# share an AWS account -- earlier cases' roles cannot appear in a later")
    print("# case's graph. Kubernetes ServiceAccounts from earlier cases may still")
    print("# exist, but their IRSA annotations point at roles that no longer exist")
    print("# post-reset, so graph.builder skips them (logged, not a false edge);")
    print("# check_live_case.py also filters by this case's own entry-SA node as")
    print("# defense in depth.")
    print("set -e")
    print("mkdir -p evaluation/generated_benchmark/live")
    print("rm -f evaluation/generated_benchmark/live/summary.jsonl evaluation/generated_benchmark/live/summary.json")
    print('export AWS_DEFAULT_REGION=us-east-1 AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test')
    for c in picked:
        for line in case_script(c):
            print(line)
    print('echo "=== live sample complete: see evaluation/generated_benchmark/live/summary.json ==="')
    print("python -m evaluation.generated_benchmark.summarize_live")


if __name__ == "__main__":
    main()
