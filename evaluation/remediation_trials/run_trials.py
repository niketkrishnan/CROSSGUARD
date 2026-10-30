#!/usr/bin/env python3
"""Live remediation trials: 4 fix types x N trials, fresh LocalStack before every trial.

For each trial:
  1. Reset: remove and restart the LocalStack container, delete the trial ServiceAccounts.
  2. Build the fixture with the repo's own benchmarks/benchN/setup_aws.sh plus ServiceAccounts.
  3. Scan (legacy semantics, as the fixtures use EC2-style trust), compute the minimum-cut fix.
  4. Apply the engine's recommended fix to the live environment and time it.
  5. Rescan and check: paths dropped to 0 and edges dropped by exactly the number of fixes.
Raw JSON per trial, a CSV and a summary are written to the output folder.

Requirements: LocalStack 4.14.0 via docker, `awslocal`, `kubectl` with a running cluster
(Minikube), and the project's Python dependencies (run inside the repo venv).

Usage (from the repo root):
    python3 evaluation/remediation_trials/run_trials.py --n 1      # smoke test
    python3 evaluation/remediation_trials/run_trials.py            # full: 10 per type
"""
from __future__ import annotations

import argparse
import copy
import csv
import datetime
import json
import logging
import os
import statistics as st
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
logging.disable(logging.WARNING)

ENDPOINT = "http://localhost:4566"
ACCT = "000000000000"
ENV = dict(os.environ, AWS_ACCESS_KEY_ID="test", AWS_SECRET_ACCESS_KEY="test",
           AWS_DEFAULT_REGION="us-east-1")

FIXTURES = {
    "irsa_bridge": dict(bench="bench1", kind="cross",
                        sas=[("vulnerable-sa", "default", "admin-role")]),
    "sts:AssumeRole": dict(bench="bench2", kind="cross",
                           sas=[("bench2-sa", "default", "b2-role-a")]),
    "iam:PassRole": dict(bench="bench8", kind="cross",
                         sas=[("bench8-sa-1", "default", "b8-role-shared"),
                              ("bench8-sa-2", "default", "b8-role-shared")]),
    "group_membership": dict(bench="bench4", kind="same", sas=[],
                             user="b4-low-priv-user"),
}


# ----------------------------------------------------------------- pure helpers
def strip_comment(cmd: str) -> str:
    """The engine appends human comments after the command; keep only the command."""
    for marker in ("   #", " # "):
        if marker in cmd:
            cmd = cmd.split(marker)[0]
    return cmd.strip()


def remove_principal_from_trust(doc: dict, src_arn: str) -> dict:
    """Remove src_arn from a role trust policy (drop statements that trusted only src)."""
    doc = copy.deepcopy(doc)
    keep = []
    for stmt in doc.get("Statement", []):
        principal = stmt.get("Principal")
        if isinstance(principal, dict) and "AWS" in principal:
            aws = principal["AWS"]
            principals = [aws] if isinstance(aws, str) else list(aws)
            principals = [p for p in principals if p != src_arn]
            if not principals:
                continue
            principal = dict(principal)
            principal["AWS"] = principals if len(principals) > 1 else principals[0]
            stmt = dict(stmt, Principal=principal)
        keep.append(stmt)
    if not keep:  # IAM rejects an empty statement list
        keep = [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                 "Action": "sts:AssumeRole"}]
    doc["Statement"] = keep
    return doc


def remove_passrole_from_policy(doc: dict, dst_arn: str) -> tuple[dict, bool]:
    """Remove iam:PassRole on dst_arn from a policy document. Returns (new_doc, changed)."""
    doc = copy.deepcopy(doc)
    out, changed = [], False
    for stmt in doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            out.append(stmt)
            continue
        acts = stmt.get("Action")
        acts_l = [acts] if isinstance(acts, str) else list(acts or [])
        res = stmt.get("Resource")
        res_l = [res] if isinstance(res, str) else list(res or [])
        if any(a.lower() == "iam:passrole" for a in acts_l) and dst_arn in res_l:
            changed = True
            others_actions = [a for a in acts_l if a.lower() != "iam:passrole"]
            other_res = [r for r in res_l if r != dst_arn]
            if other_res:  # keep PassRole on the remaining roles
                out.append(dict(stmt, Resource=other_res if len(other_res) > 1 else other_res[0]))
            if others_actions:  # keep the statement's other actions on the original resources
                out.append(dict(stmt, Action=others_actions if len(others_actions) > 1 else others_actions[0]))
            continue
        out.append(stmt)
    doc["Statement"] = out
    return doc, changed


# ----------------------------------------------------------------- environment
def sh(cmd, check=True):
    r = subprocess.run(cmd, shell=isinstance(cmd, str), env=ENV, capture_output=True,
                       text=True, cwd=str(REPO))
    if check and r.returncode != 0:
        raise RuntimeError("command failed (%d): %s\n%s" % (r.returncode, cmd, r.stderr[-500:]))
    return r


def reset_localstack() -> None:
    sh("docker rm -f localstack", check=False)
    sh("docker run -d --name localstack -p 4566:4566 localstack/localstack:4.14.0")
    deadline = time.time() + 150
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(ENDPOINT + "/_localstack/health", timeout=3) as resp:
                health = json.load(resp)
            if health.get("services", {}).get("iam") in ("available", "running"):
                time.sleep(2)
                return
        except Exception:
            pass
        time.sleep(2)
    raise RuntimeError("LocalStack did not become ready in time")


def cleanup_sas(fx: dict) -> None:
    for name, ns, _ in fx["sas"]:
        sh(["kubectl", "delete", "serviceaccount", name, "-n", ns, "--ignore-not-found"], check=False)


def build_fixture(fx: dict) -> None:
    sh("bash benchmarks/%s/setup_aws.sh" % fx["bench"])
    for name, ns, role in fx["sas"]:
        sh(["kubectl", "create", "serviceaccount", name, "-n", ns])
        sh(["kubectl", "annotate", "serviceaccount", name, "-n", ns, "--overwrite",
            "eks.amazonaws.com/role-arn=arn:aws:iam::%s:role/%s" % (ACCT, role)])


# ----------------------------------------------------------------- scan and fix
def scan(fx: dict):
    from graph.builder import build_unified_graph
    from ingestion import policy_eval as pe
    from ingestion.aws_ingestion import ingest_aws
    from ingestion.k8s_ingestion import find_irsa_mappings, ingest_k8s
    from pathfinder.search import (annotate_path_confidence, find_admin_nodes,
                                   find_all_cross_layer_paths, find_escalation_paths)
    from scoring.risk import score_all_paths

    aws = ingest_aws(profile=None, endpoint_url=ENDPOINT, region="us-east-1")
    k8s = ingest_k8s(kube_config_path=None, in_cluster=False)
    maps = find_irsa_mappings(k8s["service_accounts"])
    G = build_unified_graph(aws, k8s, maps, config=pe.LEGACY)
    if fx["kind"] == "cross":
        paths = score_all_paths(G, annotate_path_confidence(G, find_all_cross_layer_paths(G)))
    else:
        user = "arn:aws:iam::%s:user/%s" % (ACCT, fx["user"])
        paths = find_escalation_paths(G, user, find_admin_nodes(G))
    return G, paths


def apply_fix(rem: dict) -> list[str]:
    """Apply one recommended fix to the live environment. Returns the commands run."""
    et, ran = rem["edge_type"], []
    if et == "irsa_bridge":
        cmd = strip_comment(rem["command"])
        sh(cmd); ran.append(cmd)
    elif et == "group_membership":
        cmd = strip_comment(rem["command"]).replace("aws ", "awslocal ", 1)
        sh(cmd); ran.append(cmd)
    elif et == "sts:AssumeRole":
        dst = rem["target"].split("/")[-1]
        doc = json.loads(sh(["awslocal", "iam", "get-role", "--role-name", dst]).stdout)[
            "Role"]["AssumeRolePolicyDocument"]
        new = remove_principal_from_trust(doc, rem["source"])
        sh(["awslocal", "iam", "update-assume-role-policy", "--role-name", dst,
            "--policy-document", json.dumps(new)])
        ran.append("update-assume-role-policy --role-name %s (removed %s)" % (dst, rem["source"]))
    elif et == "iam:PassRole":
        src = rem["source"].split("/")[-1]
        names = json.loads(sh(["awslocal", "iam", "list-role-policies", "--role-name", src]).stdout)[
            "PolicyNames"]
        changed_any = False
        for pname in names:
            doc = json.loads(sh(["awslocal", "iam", "get-role-policy", "--role-name", src,
                                 "--policy-name", pname]).stdout)["PolicyDocument"]
            new, changed = remove_passrole_from_policy(doc, rem["target"])
            if not changed:
                continue
            changed_any = True
            if new["Statement"]:
                sh(["awslocal", "iam", "put-role-policy", "--role-name", src, "--policy-name",
                    pname, "--policy-document", json.dumps(new)])
                ran.append("put-role-policy %s/%s" % (src, pname))
            else:
                sh(["awslocal", "iam", "delete-role-policy", "--role-name", src,
                    "--policy-name", pname])
                ran.append("delete-role-policy %s/%s" % (src, pname))
        if not changed_any:
            raise RuntimeError("no inline policy of %s grants PassRole on %s" % (src, rem["target"]))
    else:
        raise RuntimeError("no live applier for edge type %s" % et)
    return ran


# ----------------------------------------------------------------- main loop
def run_trial(fix_type: str, trial: int, outdir: Path) -> dict:
    from remediation.engine import find_minimum_remediation
    fx = FIXTURES[fix_type]
    rec = dict(fix_type=fix_type, trial=trial, fixture=fx["bench"],
               started=datetime.datetime.now().isoformat(timespec="seconds"), success=False, error=None)
    try:
        reset_localstack()
        cleanup_sas(fx)
        build_fixture(fx)
        G0, paths0 = scan(fx)
        rec.update(paths_before=len(paths0), edges_before=G0.number_of_edges(),
                   nodes_before=G0.number_of_nodes())
        t0 = time.perf_counter()
        rems = find_minimum_remediation(G0, paths0)
        rec["compute_seconds"] = round(time.perf_counter() - t0, 4)
        rec["recommended"] = [dict(edge_type=r["edge_type"], source=r["source"], target=r["target"])
                              for r in rems]
        rec["expected_edge_type_matched"] = all(r["edge_type"] == fix_type for r in rems)
        t1 = time.perf_counter()
        ran = []
        for r in rems:
            ran += apply_fix(r)
        rec["fix_seconds"] = round(time.perf_counter() - t1, 4)
        rec["commands_run"] = ran
        G1, paths1 = scan(fx)
        rec.update(paths_after=len(paths1), edges_after=G1.number_of_edges())
        rec["edges_removed_as_expected"] = (rec["edges_after"] == rec["edges_before"] - len(rems))
        rec["success"] = bool(rec["paths_before"] >= 1 and rec["paths_after"] == 0
                              and rec["edges_removed_as_expected"])
    except Exception as exc:  # record and continue
        rec["error"] = str(exc)[:600]
    finally:
        try:
            cleanup_sas(fx)
        except Exception:
            pass
    (outdir / ("%s_trial%02d.json" % (fix_type.replace(":", "-"), trial))).write_text(
        json.dumps(rec, indent=2))
    return rec


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=10, help="trials per fix type")
    ap.add_argument("--types", nargs="*", default=list(FIXTURES))
    ap.add_argument("--out", default=str(REPO / "evaluation" / "remediation_trials" / "live_rerun"))
    args = ap.parse_args()
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    commit = sh("git rev-parse HEAD", check=False).stdout.strip()
    print("repo commit:", commit)
    results = []
    for fix_type in args.types:
        for t in range(1, args.n + 1):
            rec = run_trial(fix_type, t, outdir)
            results.append(rec)
            print("%-17s trial %2d  success=%-5s paths %s->%s  fix=%ss  %s" % (
                fix_type, t, rec["success"], rec.get("paths_before"), rec.get("paths_after"),
                rec.get("fix_seconds"), rec["error"] or ""), flush=True)

    summary = {"repo_commit": commit, "finished": datetime.datetime.now().isoformat(timespec="seconds"),
               "semantics": "legacy", "latency_definition":
               "wall-clock seconds to apply the recommended fix to the live environment (all CLI calls)",
               "per_type": {}}
    for fix_type in args.types:
        rs = [r for r in results if r["fix_type"] == fix_type]
        lat = [r["fix_seconds"] for r in rs if "fix_seconds" in r]
        entry = dict(trials=len(rs), succeeded=sum(r["success"] for r in rs),
                     expected_edge_type=sum(bool(r.get("expected_edge_type_matched")) for r in rs))
        if len(lat) >= 2:
            entry.update(mean_s=round(st.mean(lat), 3), stdev_s=round(st.stdev(lat), 3),
                         median_s=round(st.median(lat), 3), max_s=round(max(lat), 3))
            if len(lat) >= 3:
                trimmed = sorted(lat)[:-1]
                entry.update(mean_excl_max_s=round(st.mean(trimmed), 3),
                             stdev_excl_max_s=round(st.stdev(trimmed), 3))
        summary["per_type"][fix_type] = entry
    (outdir / "summary.json").write_text(json.dumps(summary, indent=2))
    with open(outdir / "trials.csv", "w", newline="") as fh:
        cols = ["fix_type", "trial", "success", "paths_before", "paths_after", "edges_before",
                "edges_after", "compute_seconds", "fix_seconds", "expected_edge_type_matched", "error"]
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(results)
    print(json.dumps(summary, indent=2))
    return 0 if all(r["success"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
