"""
Differential test of CrossGuard's policy evaluator against PMapper's.

PMapper (NCC Group) contains its own matcher for IAM policy statements
(principalmapper.querying.local_policy_simulation.policy_has_matching_statement).
It was written independently of CrossGuard, so agreement between the two is
evidence from a source we did not author. It is NOT ground truth: PMapper is
not AWS. Every disagreement is therefore recorded, grouped by cause, and must
be adjudicated against the AWS documentation (see the results document).

Two comparison levels, both over randomly generated cases with a seeded RNG:

  statement level -- does this single statement match (action, resource,
                     context)?  ours: statement_match(...) == "true"
  decision level  -- allow / deny / implicit-deny for a whole policy:
                     ours: decide(...); PMapper: an Allow match, a Deny match,
                     Deny winning.

Every condition key used in a generated statement is given a value in the
context, or is explicitly known-absent (ABSENT here, omitted for PMapper), so
CrossGuard's evaluator has everything it needs and should never answer
"unknown". A separate section confirms that unsupported operators and policy
variables DO come back "unknown" rather than a wrong true/false.

Usage:
    python -m evaluation.policy_semantics.differential.run_differential [N] [SEED] [controlled]
"""

from __future__ import annotations

import collections
import collections.abc
import json
import os
import random
import sys
from collections import Counter, defaultdict

# principalmapper 1.1.5 still does `from collections import Mapping`
for _n in ("Mapping", "MutableMapping"):
    if not hasattr(collections, _n):
        setattr(collections, _n, getattr(collections.abc, _n))

from principalmapper.querying.local_policy_simulation import policy_has_matching_statement  # noqa: E402
from principalmapper.util.case_insensitive_dict import CaseInsensitiveDict  # noqa: E402

from ingestion import policy_eval as pe  # noqa: E402

ACTIONS = ["s3:GetObject", "s3:PutObject", "iam:PassRole", "iam:CreateRole", "ec2:RunInstances", "sts:AssumeRole"]
ACTION_PATTERNS = ACTIONS + ["*", "s3:*", "iam:*", "s3:Get*", "S3:getobject", "iam:Pass?ole", "ec2:*", "sts:Assume*"]
RESOURCES = [
    "arn:aws:s3:::bucket1/key1", "arn:aws:s3:::bucket2/key2",
    "arn:aws:iam::123456789012:role/app-admin", "arn:aws:iam::123456789012:role/Team-A",
    "arn:aws:iam::123456789012:role/app-reader",
]
RESOURCE_PATTERNS = RESOURCES + [
    "*", "arn:aws:s3:::bucket1/*", "arn:aws:iam::*:role/app-*", "arn:aws:iam::123456789012:role/*",
    "arn:aws:iam::123456789012:role/app-ADMIN", "arn:aws:iam::123456789012:role/team-a",
    "arn:aws:iam::123456789012:role/app-?dmin", "arn:aws:s3:::*",
]

# (key, kind, value pool). kind: str | arn | bool
COND_KEYS = [
    ("iam:PassedToService", "str", ["ec2.amazonaws.com", "lambda.amazonaws.com", "glue.amazonaws.com"]),
    ("aws:RequestTag/env", "str", ["prod", "dev", "prod-eu", "Prod"]),
    ("aws:userid", "str", ["AIDA1", "AIDA2", "AROA9"]),
    ("aws:PrincipalArn", "arn", ["arn:aws:iam::123456789012:role/app-admin", "arn:aws:iam::123456789012:role/Team-A",
                                 "arn:aws:iam::999999999999:user/bob"]),
    ("aws:MultiFactorAuthPresent", "bool", ["true", "false"]),
]
STR_OPS = ["StringEquals", "StringNotEquals", "StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase",
           "StringLike", "StringNotLike"]
ARN_OPS = ["ArnEquals", "ArnLike", "ArnNotEquals", "ArnNotLike"]
POLICY_PATTERN_POOL = {
    "str": ["ec2.amazonaws.com", "lambda.amazonaws.com", "*.amazonaws.com", "prod", "prod*", "Prod", "dev", "AIDA1", "AIDA*", "?IDA1"],
    "arn": ["arn:aws:iam::123456789012:role/app-admin", "arn:aws:iam::*:role/*", "arn:aws:iam::123456789012:role/team-a",
            "arn:aws:iam::999999999999:user/*"],
    "bool": ["true", "false"],
}


ABSENT_PROB = 0.25


def set_controlled():
    """Positive control: remove the two stimuli behind the attributed causes
    (case-variant ARN patterns; absent condition keys). If the two engines
    then agree everywhere, the remaining disagreements really are confined to
    those causes."""
    global ABSENT_PROB
    ABSENT_PROB = 0.0
    for lst in (RESOURCE_PATTERNS,):
        lst[:] = [x for x in lst if x not in ("arn:aws:iam::123456789012:role/app-ADMIN",
                                              "arn:aws:iam::123456789012:role/team-a")]
    POLICY_PATTERN_POOL["arn"][:] = [x for x in POLICY_PATTERN_POOL["arn"] if x != "arn:aws:iam::123456789012:role/team-a"]


def _condition(rng):
    cond = {}
    for _ in range(rng.choice([1, 1, 2])):
        key, kind, pool = rng.choice(COND_KEYS)
        if kind == "bool":
            op = rng.choice(["Bool", "BoolIfExists", "Null"])
        elif kind == "arn":
            op = rng.choice(ARN_OPS + [o + "IfExists" for o in ARN_OPS[:2]] + ["Null"])
        else:
            op = rng.choice(STR_OPS + [o + "IfExists" for o in STR_OPS[:3]] + ["Null"])
        if op == "Null":
            val = rng.choice(["true", "false"])
        else:
            val = rng.sample(POLICY_PATTERN_POOL[kind], rng.choice([1, 1, 2]))
            val = val if len(val) > 1 else val[0]
        cond.setdefault(op, {})[key] = val
    return cond


def gen_statement(rng):
    st = {"Effect": rng.choice(["Allow", "Allow", "Deny"])}
    acts = rng.sample(ACTION_PATTERNS, rng.choice([1, 1, 2]))
    st["NotAction" if rng.random() < 0.12 else "Action"] = acts if len(acts) > 1 else acts[0]
    ress = rng.sample(RESOURCE_PATTERNS, rng.choice([1, 1, 2]))
    st["NotResource" if rng.random() < 0.12 else "Resource"] = ress if len(ress) > 1 else ress[0]
    if rng.random() < 0.55:
        st["Condition"] = _condition(rng)
    return st


def gen_context(rng):
    """Every condition key gets a value or is known-absent."""
    ctx_ours, ctx_pm = {}, {}
    for key, kind, pool in COND_KEYS:
        if rng.random() < ABSENT_PROB:
            ctx_ours[key.lower()] = pe.ABSENT
        else:
            v = rng.choice(pool)
            ctx_ours[key.lower()] = v
            ctx_pm[key] = v
    return ctx_ours, CaseInsensitiveDict(ctx_pm)


def pm_match(stmt, action, resource, ctx_pm):
    return policy_has_matching_statement({"Statement": [stmt]}, stmt["Effect"], action, resource, ctx_pm)


def pm_decision(stmts, action, resource, ctx_pm):
    pol = {"Statement": stmts}
    if policy_has_matching_statement(pol, "Deny", action, resource, ctx_pm):
        return "deny"
    if policy_has_matching_statement(pol, "Allow", action, resource, ctx_pm):
        return "allow"
    return "implicit_deny"


def features(stmt):
    f = set()
    f.add("NotAction" if "NotAction" in stmt else "Action")
    f.add("NotResource" if "NotResource" in stmt else "Resource")
    for op, kv in stmt.get("Condition", {}).items():
        f.add("op:" + op)
        if op.endswith("IfExists"):
            f.add("IfExists")
        if op.startswith(("StringNot", "ArnNot")):
            f.add("negated-op")
    return sorted(f)



CAT_RES_CASE = "resource ARN matched case-insensitively by PMapper (AWS: case-sensitive)"
CAT_ARN_CASE = "ARN condition operator matched case-insensitively by PMapper (AWS: case-sensitive)"
CAT_NEG_ABSENT = "StringNotLike with an absent key returns false in PMapper (AWS: true)"
CAT_UNEXPLAINED = "UNEXPLAINED"


def _ctx_from_row(c):
    o = {k: (pe.ABSENT if v == "<absent>" else v) for k, v in c.items()}
    p = CaseInsensitiveDict({k: v for k, v in c.items() if v != "<absent>"})
    return o, p


def _lower_arns(x):
    if isinstance(x, list):
        return [_lower_arns(i) for i in x]
    return x.lower() if isinstance(x, str) else x


def attribute(row):
    """Return the list of causes that explain a statement-level disagreement.

    Each cause is only claimed when a targeted check confirms it:
      * component isolation says which of Action / Resource / Condition differs;
      * case causes are confirmed by re-running OUR evaluator with that
        component lower-cased and checking that it then agrees with PMapper;
      * the absent-key cause is confirmed by at least one key of the operator
        being absent, the operator being StringNotLike without IfExists,
        PMapper answering false and ours true.
    """
    st, a, res = row["stmt"], row["action"], row["resource"]
    o, p = _ctx_from_row(row["context"])
    causes = set()

    # Resource component
    sr = {"Effect": "Allow", "Action": "*", **{k: v for k, v in st.items() if k in ("Resource", "NotResource")}}
    ours_r = pe.statement_match(sr, a, res, o) == pe.TRUE
    pm_r = policy_has_matching_statement({"Statement": [sr]}, "Allow", a, res, p)
    if ours_r != pm_r:
        sr_l = {k: (_lower_arns(v) if k in ("Resource", "NotResource") else v) for k, v in sr.items()}
        if (pe.statement_match(sr_l, a, res.lower(), o) == pe.TRUE) == pm_r:
            causes.add(CAT_RES_CASE)
        else:
            causes.add(CAT_UNEXPLAINED)

    # Condition component, operator by operator
    for op, kv in st.get("Condition", {}).items():
        sc = {"Effect": "Allow", "Action": "*", "Resource": "*", "Condition": {op: kv}}
        ours_c = pe.statement_match(sc, a, res, o) == pe.TRUE
        pm_c = policy_has_matching_statement({"Statement": [sc]}, "Allow", a, res, p)
        if ours_c == pm_c:
            continue
        base = op[:-8] if op.endswith("IfExists") else op
        keys = list(kv)
        any_absent = any(o.get(k.lower()) is pe.ABSENT for k in keys)
        if (any_absent and base == "StringNotLike" and not op.endswith("IfExists")
                and ours_c and not pm_c):
            causes.add(CAT_NEG_ABSENT)
            continue
        if base.startswith("Arn"):
            kv_l = {k: _lower_arns(v) for k, v in kv.items()}
            o_l = {k: (v.lower() if isinstance(v, str) else v) for k, v in o.items()}
            sc_l = {"Effect": "Allow", "Action": "*", "Resource": "*", "Condition": {op: kv_l}}
            if (pe.statement_match(sc_l, a, res, o_l) == pe.TRUE) == pm_c:
                causes.add(CAT_ARN_CASE)
                continue
        causes.add(CAT_UNEXPLAINED)
    if not causes:
        causes.add(CAT_UNEXPLAINED)   # statement disagrees but no component does: composition issue
    return sorted(causes)


def main(n=20000, seed=20260919, controlled=False, outdir=None):
    if controlled:
        set_controlled()
    rng = random.Random(seed)
    stmt_total = stmt_agree = 0
    stmt_dis = []
    dec_total = dec_agree = 0
    dec_dis = []
    unknown_from_ours = 0
    stmt_true = 0
    dec_dist = Counter()
    feat_total, feat_dis = Counter(), Counter()

    for i in range(n):
        stmt = gen_statement(rng)
        action, resource = rng.choice(ACTIONS), rng.choice(RESOURCES)
        ctx_o, ctx_p = gen_context(rng)

        ours = pe.statement_match(stmt, action, resource, ctx_o)
        theirs = pm_match(stmt, action, resource, ctx_p)
        stmt_total += 1
        stmt_true += ours == pe.TRUE
        if ours == pe.UNKNOWN:
            unknown_from_ours += 1
        for f in features(stmt):
            feat_total[f] += 1
        if (ours == pe.TRUE) == theirs and ours != pe.UNKNOWN:
            stmt_agree += 1
        else:
            for f in features(stmt):
                feat_dis[f] += 1
            stmt_dis.append({"stmt": stmt, "action": action, "resource": resource,
                             "context": {k: ("<absent>" if v is pe.ABSENT else v) for k, v in ctx_o.items()},
                             "ours": ours, "pmapper": theirs})

        # decision level: 1-4 statements sharing one request
        stmts = [gen_statement(rng) for _ in range(rng.choice([1, 2, 3, 4]))]
        d_ours = pe.decide(stmts, action, resource, ctx_o)
        d_pm = pm_decision(stmts, action, resource, ctx_p)
        dec_total += 1
        dec_dist[d_pm] += 1
        norm = "allow" if d_ours in ("allow",) else d_ours
        if norm == d_pm:
            dec_agree += 1
        else:
            dec_dis.append({"stmts": stmts, "action": action, "resource": resource,
                            "context": {k: ("<absent>" if v is pe.ABSENT else v) for k, v in ctx_o.items()},
                            "ours": d_ours, "pmapper": d_pm})

    # unsupported operators / variables must be UNKNOWN, never a wrong definite answer
    probes = [
        {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
        {"NumericLessThan": {"aws:MultiFactorAuthAge": "3600"}},
        {"DateGreaterThan": {"aws:CurrentTime": "2020-01-01T00:00:00Z"}},
        {"ForAnyValue:StringEquals": {"aws:RequestTag/env": "prod"}},
        {"StringEquals": {"aws:userid": "${aws:username}"}},
    ]
    ctx = {"aws:sourceip": "10.1.1.1", "aws:multifactorauthage": "10", "aws:currenttime": "2026-01-01T00:00:00Z",
           "aws:requesttag/env": "prod", "aws:userid": "AIDA1"}
    unsupported_ok = all(pe.evaluate_condition(c, ctx) == pe.UNKNOWN for c in probes)

    cause_counts = Counter()
    cause_examples = {}
    for d in stmt_dis:
        cs = attribute(d)
        d["causes"] = cs
        for c in cs:
            cause_counts[c] += 1
            cause_examples.setdefault(c, d)
    # a decision-level disagreement is explained only if at least one of its
    # statements disagrees at statement level
    dec_unexplained = 0
    for d in dec_dis:
        ctx_o, ctx_p = _ctx_from_row(d["context"])
        any_stmt = any((pe.statement_match(x, d["action"], d["resource"], ctx_o) == pe.TRUE) !=
                       pm_match(x, d["action"], d["resource"], ctx_p) for x in d["stmts"])
        d["explained_by_statement_disagreement"] = any_stmt
        if not any_stmt:
            dec_unexplained += 1

    out = {
        "seed": seed, "n": n, "controlled": controlled, "pmapper_version": "1.1.5",
        "statement_level": {"total": stmt_total, "agree": stmt_agree,
                            "agreement": round(stmt_agree / stmt_total, 4), "disagree": len(stmt_dis),
                            "ours_unknown": unknown_from_ours,
                            "statements_matching": stmt_true,
                            "match_rate": round(stmt_true / stmt_total, 4)},
        "decision_level": {"total": dec_total, "agree": dec_agree,
                           "agreement": round(dec_agree / dec_total, 4), "disagree": len(dec_dis),
                           "outcome_distribution_pmapper": dict(dec_dist)},
        "feature_disagreement_rates": {f: {"cases": feat_total[f], "disagree": feat_dis[f],
                                           "rate": round(feat_dis[f] / feat_total[f], 4)}
                                       for f in sorted(feat_total)},
        "unsupported_operators_return_unknown": unsupported_ok,
        "statement_disagreement_causes": dict(cause_counts.most_common()),
        "decision_disagreements_not_explained_by_a_statement_disagreement": dec_unexplained,
    }
    here = outdir or os.path.dirname(__file__)
    suffix = "_controlled" if controlled else ""
    with open(os.path.join(here, f"differential_summary{suffix}.json"), "w") as f:
        json.dump(out, f, indent=1)
    with open(os.path.join(here, f"statement_disagreements{suffix}.jsonl"), "w") as f:
        for d in stmt_dis:
            f.write(json.dumps(d) + "\n")
    with open(os.path.join(here, f"cause_examples{suffix}.json"), "w") as f:
        json.dump({c: {k: v for k, v in ex.items() if k != "causes"} for c, ex in cause_examples.items()}, f, indent=1)
    with open(os.path.join(here, f"decision_disagreements{suffix}.jsonl"), "w") as f:
        for d in dec_dis:
            f.write(json.dumps(d) + "\n")
    return out


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 20000
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 20260919
    controlled = len(sys.argv) > 3 and sys.argv[3] == "controlled"
    print(json.dumps(main(n, seed, controlled), indent=1))
