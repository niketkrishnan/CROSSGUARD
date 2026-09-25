"""
Replay: re-run the B10 (false-positive stress) and B11 (adversarial)
fixtures, plus targeted regression fixtures, under three evaluator modes:

  legacy  -- original presence-only behaviour (the "before")
  annotate -- Deny / Condition / PassRole pairing / wildcard trust evaluated; every
              edge kept and labelled (shows what strict would drop)
  strict   -- same checks, plus edges that are DEFINITELY unusable (invalid IRSA trust,
              PassRole target no service can assume) are dropped and logged. Default.

IMPORTANT
  * This is an OFFLINE replay: the fixtures below are Python transcriptions of
    benchmarks/bench10/setup_aws.sh and benchmarks/bench11/setup_aws.sh, fed
    straight to graph.builder. It does NOT touch LocalStack. The LocalStack
    re-run (live_rerun.sh, see POLICY_SEMANTICS_EVALUATION.md) is what
    confirms the transcription is faithful.
  * The `truth` labels are the AUTHOR's reading of AWS semantics. They are
    not an independent oracle. They are pending replacement by oracle-derived labels.
  * Each original fixture uses EC2 service trust on roles that are reached
    through IRSA. Real IRSA needs a Federated OIDC trust. We therefore run
    every case twice: "as-built" (original trust policies) and "irsa-realistic"
    (trust rewritten to a proper OIDC trust for ServiceAccount-bound roles, all
    other policy content unchanged), so that Deny/Condition/PassRole logic is
    tested in isolation from the trust-policy realism problem.

Usage:  python -m evaluation.policy_semantics.replay
"""

from __future__ import annotations

import copy
import json
import os
import types
from collections import OrderedDict

import logging

from graph.builder import build_unified_graph
from ingestion import policy_eval as pe
from ingestion.policy_utils import extract_passrole_resources, extract_trust_principals

logging.disable(logging.WARNING)
from pathfinder.search import annotate_path_confidence, find_all_cross_layer_paths

A = "000000000000"
OIDC = f"arn:aws:iam::{A}:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"
K = "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"
ADMIN = {"Effect": "Allow", "Action": "*", "Resource": "*"}
EC2 = {"Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}


def arn(n): return f"arn:aws:iam::{A}:role/{n}"


def oidc_trust(sa, ns="default", extra_cond=None):
    st = {"Effect": "Allow", "Principal": {"Federated": OIDC}, "Action": "sts:AssumeRoleWithWebIdentity",
          "Condition": {"StringEquals": {f"{K}:sub": f"system:serviceaccount:{ns}:{sa}",
                                         f"{K}:aud": "sts.amazonaws.com"}}}
    if extra_cond:
        st["Condition"].update(extra_cond)
    return {"Statement": [st]}


def R(name, trust=EC2, stmts=None, admin=False):
    """Mirror what ingestion.aws_ingestion._enrich_role produces, so the legacy
    mode sees exactly the fields the original builder consumed."""
    docs = [{"Statement": stmts}] if stmts else []
    pr = []
    for d in docs:
        pr.extend(extract_passrole_resources(d))
    return {"Arn": arn(name), "RoleName": name, "is_admin": admin, "AssumeRolePolicyDocument": trust,
            "policy_documents": docs, "trust_principals": extract_trust_principals(trust),
            "passrole_resources": pr}


def SA(name, ns="default"):
    o = types.SimpleNamespace(); o.metadata = types.SimpleNamespace(name=name, namespace=ns, annotations=None)
    return o


def allow(action, resource="*", cond=None):
    s = {"Effect": "Allow", "Action": action, "Resource": resource}
    if cond:
        s["Condition"] = cond
    return s


def aws_trust(*arns, service=True):
    st = [{"Effect": "Allow", "Principal": {"AWS": a}, "Action": "sts:AssumeRole"} for a in arns]
    if service:
        st.append(EC2["Statement"][0])
    return {"Statement": st}


# ---------------------------------------------------------------------------
# Fixtures. Each: roles, sa->role mapping, truth, note.
#   truth: none | exploitable | exposure | conditional
# ---------------------------------------------------------------------------

def b10():
    C = OrderedDict()
    def add(cid, roles, maps, truth, note): C[cid] = dict(roles=roles, maps=maps, truth=truth, note=note)
    ro = lambda n: R(n)   # managed read-only policies: not admin, no escalation actions
    add("B10-01 s3-readonly", [ro("b10-s3-readonly")], {"b10-s3-readonly": "b10-s3-readonly"}, "none", "")
    add("B10-02 ddb-readonly", [ro("b10-ddb-readonly")], {"b10-ddb-readonly": "b10-ddb-readonly"}, "none", "")
    add("B10-03 cw-readonly", [ro("b10-cw-readonly")], {"b10-cw-readonly": "b10-cw-readonly"}, "none", "")
    add("B10-04 scoped-passrole",
        [ro("b10-passrole-target"),
         R("b10-passrole-scoped", stmts=[allow("iam:PassRole", arn("b10-passrole-target"))])],
        {"b10-passrole-scoped": "b10-passrole-scoped"}, "none", "PassRole to a non-admin role")
    add("B10-05 logs-wildcard", [R("b10-logs-wildcard", stmts=[allow("logs:*")])], {"b10-logs-wildcard": "b10-logs-wildcard"}, "none", "")
    add("B10-06 s3-scoped-star", [R("b10-s3-scoped-star", stmts=[allow("s3:*", ["arn:aws:s3:::b10-app-bucket", "arn:aws:s3:::b10-app-bucket/*"])])],
        {"b10-s3-scoped-star": "b10-s3-scoped-star"}, "none", "")
    add("B10-07 iam-readonly", [R("b10-iam-readonly", stmts=[allow(["iam:GetRole", "iam:ListRoles"])])], {"b10-iam-readonly": "b10-iam-readonly"}, "none", "")
    add("B10-08 minimal", [R("b10-minimal", stmts=[allow("sts:GetCallerIdentity")])], {"b10-minimal": "b10-minimal"}, "none", "")
    add("B10-09 ec2-describe", [R("b10-ec2-describe", stmts=[allow("ec2:Describe*")])], {"b10-ec2-describe": "b10-ec2-describe"}, "none", "")
    add("B10-10 safe-assume-chain",
        [R("b10-chain-end", trust=aws_trust(arn("b10-chain-start"))),
         R("b10-chain-start", stmts=[allow("sts:AssumeRole", arn("b10-chain-end"))])],
        {"b10-chain-start": "b10-chain-start"}, "none", "chain ends at a read-only role")
    add("B10-11 scoped-group", [], {}, "none", "bare IAM group, no ServiceAccount binding (N/A to path search)")
    add("B10-12 passrole-conditioned (PassedToService=ec2, Resource *)",
        [R("b10-passrole-conditioned", stmts=[allow("iam:PassRole", "*", {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}})]),
         R("b10-mfa-gated-admin", trust={"Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole",
                                                         "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}]},
           stmts=[ADMIN], admin=True),
         R("b10-explicit-deny-admin", stmts=[ADMIN, {"Effect": "Deny", "Action": "*", "Resource": "*"}], admin=True)],
        {"b10-passrole-conditioned": "b10-passrole-conditioned"}, "none",
        "PassRole+PassedToService=ec2 to admin-labelled roles; no ec2:RunInstances granted; one target MFA-gated, one all-Deny")
    add("B10-13 dangling-assume", [ro("b10-s3-readonly-2"), R("b10-dangling", stmts=[allow("sts:AssumeRole", arn("b10-s3-readonly-2"))])], {}, "none", "no IRSA annotation at all")
    add("B10-14 mfa-gated-admin (IRSA binds the admin role directly)",
        [R("b10-mfa-gated-admin", trust={"Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole",
                                                         "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}]}, stmts=[ADMIN], admin=True)],
        {"b10-mfa-gated-admin": "b10-mfa-gated-admin"}, "none", "MFA condition can never be met by web identity")
    add("B10-15 explicit-deny-admin (IRSA binds the admin role directly)",
        [R("b10-explicit-deny-admin", stmts=[ADMIN, {"Effect": "Deny", "Action": "*", "Resource": "*"}], admin=True)],
        {"b10-explicit-deny-admin": "b10-explicit-deny-admin"}, "none", "Deny * wins in AWS evaluation")
    return C


def b11():
    C = OrderedDict()
    def add(cid, roles, maps, truth, note): C[cid] = dict(roles=roles, maps=maps, truth=truth, note=note)
    add("B11-01 wildcard-principal-admin (IRSA binds it directly)",
        [R("b11-wildcard-principal-admin", trust={"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]}, stmts=[ADMIN], admin=True)],
        {"b11-wildcard-principal-admin": "b11-wildcard-principal-admin"}, "exposure",
        "publicly assumable admin role: a real exposure, but NOT an IRSA path (no OIDC trust)")
    nested = {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}, "StringLike": {"aws:RequestTag/Environment": "prod*"}, "Bool": {"aws:SecureTransport": "true"}}
    add("B11-02 nested-conditions PassRole",
        [R("b11-nested-conditions-target", stmts=[ADMIN], admin=True),
         R("b11-nested-conditions", stmts=[allow("iam:PassRole", arn("b11-nested-conditions-target"), nested)])],
        {"b11-nested-conditions": "b11-nested-conditions"}, "conditional",
        "PassRole gated by RequestTag/SecureTransport; no paired action")
    add("B11-03 5-hop chain",
        [R("b11-hop4-admin", trust=aws_trust(arn("b11-hop3"), service=False), stmts=[ADMIN], admin=True),
         R("b11-hop3", trust=aws_trust(arn("b11-hop2")), stmts=[allow("iam:PassRole", arn("b11-hop4-admin"))]),
         R("b11-hop2", stmts=[allow("sts:AssumeRole", arn("b11-hop3"))]),
         R("b11-hop1", stmts=[allow("iam:PassRole", arn("b11-hop2"))])],
        {"b11-hop1": "b11-hop1"}, "conditional", "reachable, but hop1->hop2 is a bare PassRole")
    add("B11-04 circular trust (no admin)",
        [R("b11-circular-a", trust=aws_trust(arn("b11-circular-b"), service=False), stmts=[allow("s3:GetObject")]),
         R("b11-circular-b", trust=aws_trust(arn("b11-circular-a"), service=False))],
        {"b11-circular-a": "b11-circular-a"}, "none", "cycle must terminate with 0 paths")
    return C


def regressions():
    C = OrderedDict()
    def add(cid, roles, maps, truth, note): C[cid] = dict(roles=roles, maps=maps, truth=truth, note=note)
    can_assume = [allow("sts:AssumeRole")]
    wt = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]}
    wt_org = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole",
                             "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}}]}
    add("X-01 wildcard trust, caller may AssumeRole",
        [R("x-entry", stmts=can_assume), R("x-open-admin", trust=wt, stmts=[ADMIN], admin=True)],
        {"x-app": "x-entry"}, "exploitable", "IRSA role can assume a wildcard-trust admin role")
    add("X-02 wildcard trust, caller lacks AssumeRole",
        [R("x-entry", stmts=[allow("s3:GetObject")]), R("x-open-admin", trust=wt, stmts=[ADMIN], admin=True)],
        {"x-app": "x-entry"}, "none", "no identity-side permission")
    add("X-03 wildcard trust gated by PrincipalOrgID",
        [R("x-entry", stmts=can_assume), R("x-org-admin", trust=wt_org, stmts=[ADMIN], admin=True)],
        {"x-app": "x-entry"}, "conditional", "org membership unknowable statically")
    add("X-04 PassRole glob resource -> admin",
        [R("x-entry", stmts=[allow("iam:PassRole", f"arn:aws:iam::{A}:role/app-*"), allow("ec2:RunInstances")]),
         R("app-admin", stmts=[ADMIN], admin=True)],
        {"x-app": "x-entry"}, "exploitable", "glob Resource + paired ec2:RunInstances; original builder treats the glob as a literal ARN")
    add("X-05 PassRole + paired action (lambda) -> admin",
        [R("x-entry", stmts=[allow("iam:PassRole", arn("x-lambda-admin")), allow(["lambda:CreateFunction", "lambda:InvokeFunction"])]),
         R("x-lambda-admin", trust={"Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}, stmts=[ADMIN], admin=True)],
        {"x-app": "x-entry"}, "exploitable", "Rhino-documented technique")
    add("X-06 PassRole to admin whose trust lists no service",
        [R("x-entry", stmts=[allow("iam:PassRole", arn("x-fed-admin")), allow("ec2:RunInstances")]),
         R("x-fed-admin", trust={"Statement": [{"Effect": "Allow", "Principal": {"AWS": arn("someone-else")}, "Action": "sts:AssumeRole"}]}, stmts=[ADMIN], admin=True)],
        {"x-app": "x-entry"}, "none", "no service can assume the target, so the PassRole is unusable")
    add("X-07 admin with conditional Deny",
        [R("x-entry", stmts=[ADMIN, {"Effect": "Deny", "Action": "*", "Resource": "*", "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}}], admin=True)],
        {"x-app": "x-entry"}, "conditional", "Deny gated by source IP")
    add("X-08 correct IRSA admin (positive control)",
        [R("x-entry", stmts=[ADMIN], admin=True)], {"x-app": "x-entry"}, "exploitable", "plain direct IRSA -> admin with valid OIDC trust")
    return C


def realistic(case):
    """Rewrite trust of ServiceAccount-bound roles to a real OIDC trust, keeping
    any AWS/Service principals the original trust had. Content otherwise unchanged."""
    c = copy.deepcopy(case)
    bound = {}
    for sa, role in c["maps"].items():
        bound.setdefault(role, []).append(sa)
    for r in c["roles"]:
        sas = bound.get(r["RoleName"])
        if not sas:
            continue
        orig = r["AssumeRolePolicyDocument"]
        mfa = any("aws:MultiFactorAuthPresent" in json.dumps(s.get("Condition", {})) for s in orig["Statement"])
        keep = [s for s in orig["Statement"] if not (s.get("Principal", {}).get("Service") and "Condition" not in s)]
        # IRSA statement(s) for each bound SA, MFA condition carried over if the original had one
        irsa = []
        for sa in sas:
            t = oidc_trust(sa, extra_cond=None)["Statement"][0]
            if mfa:
                t["Condition"]["Bool"] = {"aws:MultiFactorAuthPresent": "true"}
            irsa.append(t)
        r["AssumeRolePolicyDocument"] = {"Statement": irsa + [s for s in keep if s.get("Principal", {}).get("AWS") is not None]}
        r["trust_principals"] = extract_trust_principals(r["AssumeRolePolicyDocument"])
    return c


def build(case, cfg):
    aws = {"users": [], "groups": [], "roles": copy.deepcopy(case["roles"])}
    sas = [SA(s) for s in case["maps"]]
    maps = [{"service_account": s, "namespace": "default", "aws_role_arn": arn(r)} for s, r in case["maps"].items()]
    k8s = {"service_accounts": sas, "roles": [], "role_bindings": [], "cluster_roles": [], "cluster_role_bindings": []}
    G = build_unified_graph(aws, k8s, maps, config=cfg)
    paths = annotate_path_confidence(G, find_all_cross_layer_paths(G))
    return G, paths


MODES = OrderedDict([("legacy", pe.LEGACY), ("annotate", pe.ANNOTATE), ("strict", pe.STRICT)])


def tally(paths):
    t = {"confirmed": 0, "potential": 0, "unresolved": 0}
    for p in paths:
        t[p["confidence"]] += 1
    return t


def run_suite(name, cases, variant):
    rows = []
    for cid, case in cases.items():
        c = realistic(case) if variant == "irsa-realistic" else case
        row = {"suite": name, "variant": variant, "case": cid, "truth": case["truth"], "note": case["note"], "modes": {}}
        for mode, cfg in MODES.items():
            G, paths = build(c, cfg)
            row["modes"][mode] = {
                **tally(paths),
                "exposure_findings": len(G.graph.get("wildcard_trust_roles", [])) if cfg.wildcard_trust else 0,
                "suppressed": [s["reason"] for s in G.graph.get("suppressed_edges", [])],
                "irsa_trust": sorted({p["irsa_trust"] for p in paths if p["irsa_trust"]}),
            }
        rows.append(row)
    return rows


def verdict(truth, m, level):
    """Compare against truth at a reporting level:
       'confirmed'   -> count confirmed only
       'flagged'     -> confirmed + potential (recall-favouring tier)
       'any'         -> confirmed + potential + unresolved
    Returns TP/FP/FN/TN for the case (case-level, not path-level)."""
    n = m["confirmed"] if level == "confirmed" else m["confirmed"] + m["potential"] if level == "flagged" \
        else m["confirmed"] + m["potential"] + m["unresolved"]
    exposure = m["exposure_findings"] > 0
    if truth == "none":
        return "FP" if n > 0 else "TN"
    if truth == "exploitable":
        return "TP" if n > 0 else "FN"
    if truth == "exposure":
        return "TP" if exposure else "FN"
    if truth == "conditional":       # not decidable statically: report but don't score
        return "COND"
    return "?"


def summarize(rows):
    out = OrderedDict()
    for variant in ("as-built", "irsa-realistic"):
        for mode in MODES:
            for level in ("confirmed", "flagged", "any"):
                c = {"TP": 0, "FP": 0, "FN": 0, "TN": 0, "COND": 0}
                for r in rows:
                    if r["variant"] != variant:
                        continue
                    c[verdict(r["truth"], r["modes"][mode], level)] += 1
                out[f"{variant}|{mode}|{level}"] = c
    return out


def main():
    rows = []
    for variant in ("as-built", "irsa-realistic"):
        rows += run_suite("B10", b10(), variant)
        rows += run_suite("B11", b11(), variant)
        rows += run_suite("REG", regressions(), variant)
    summ = summarize(rows)
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "replay_results.json"), "w") as f:
        json.dump({"rows": rows, "summary": summ}, f, indent=1)
    return rows, summ


def print_matrix(rows):
    for variant in ("as-built", "irsa-realistic"):
        print(f"\n== {variant} ==  (confirmed/potential/unresolved paths; exposure findings)")
        for r in rows:
            if r["variant"] != variant:
                continue
            cells = []
            for mode in MODES:
                m = r["modes"][mode]
                cells.append(f"{mode}:{m['confirmed']}/{m['potential']}/{m['unresolved']}" + (f"+E{m['exposure_findings']}" if m["exposure_findings"] else ""))
            print(f"{r['case'][:58]:58s} truth={r['truth']:11s} " + "  ".join(cells))


if __name__ == "__main__":
    rows, summ = main()
    print_matrix(rows)
    print()
    for k, v in summ.items():
        print(f"{k:38s} {v}")
