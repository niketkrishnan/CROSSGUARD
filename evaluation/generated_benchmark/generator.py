"""
evaluation/generated_benchmark/generator.py

Generates a large, labelled benchmark of AWS IAM + Kubernetes RBAC graphs
for CrossGuard, addressing the core weakness of B1-B11: those 9-15 cases
were hand-labelled by the tool's own authors. This generator instead builds
each case from a RECIPE that fixes, by construction, which mechanisms are
present and whether each is designed to work. The recipe's declared outcome
is the label. A separate, independently-coded checker (`oracle.py`) re-derives
the label straight from the generated JSON without importing anything from
`ingestion.policy_eval`, so the label is not just "whatever our own evaluator
says" -- see oracle.py's module docstring for what independence means and
does not mean here.

Every IRSA-bound role in every case gets a REAL OIDC federated trust
statement (finding 1 of POLICY_SEMANTICS_EVALUATION.md: none of the existing
B1-B11 fixtures had one). Roles that are meant to be reachable only via a
same-layer AWS mechanism (AssumeRole chains, PassRole) are not IRSA-bound
themselves; only the chain's IRSA-bound entry point is.

Recipe categories:
  hard_positive        -- a real path exists; CrossGuard should find it and
                           should assign it the confidence the recipe intends
                           (confirmed or potential)
  hard_negative         -- structurally close to a positive but broken by one
                           specific thing (wrong trust subject, MFA gate,
                           explicit Deny, untrusted PassRole target, a broken
                           link in a chain); CrossGuard should find nothing
  decoy                 -- looks like a positive at a glance (an IRSA
                           annotation near an admin-labelled role, or a
                           RoleBinding to a cluster-admin-like ClusterRole)
                           but has no real cross-layer mechanism connecting
                           them; CrossGuard should find nothing
  unresolved_by_design  -- the correct static answer is "cannot be decided
                           without runtime context" (an IP-address or
                           request-tag condition); CrossGuard should report
                           it as `unresolved`, not confirmed and not silently
                           dropped

Each case also gets 0-6 unrelated "noise" roles/statements so a tool that
merely flags "any IRSA annotation near any admin role" would be caught by
false positives on noise that structurally resembles a positive but has no
generated mechanism connecting it to the entry ServiceAccount.

Usage:
    python -m evaluation.generated_benchmark.generator --n 2000 --seed 30001 \
        --split dev --out evaluation/generated_benchmark/dev_cases.jsonl
"""

from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass, field
from typing import Any

ACCOUNT = "000000000000"   # LocalStack's real default test account (see replay.py); the offline
                           # harness never touches real AWS/LocalStack so this is self-consistent
                           # either way, but the live sample only works if it matches LocalStack.
REGION = "us-east-1"
CLUSTER_OIDC_ID = "EXAMPLED539D4633E53DE1B71EXAMPLE"
OIDC_HOST = f"oidc.eks.{REGION}.amazonaws.com/id/{CLUSTER_OIDC_ID}"
OIDC_PROVIDER_ARN = f"arn:aws:iam::{ACCOUNT}:oidc-provider/{OIDC_HOST}"
ADMIN_STMT = {"Effect": "Allow", "Action": "*", "Resource": "*"}
AUD = "sts.amazonaws.com"

PAIRED_ACTIONS = {   # kept in sync with ingestion.policy_eval.PAIRED_ACTION_CATALOG
    "ec2.amazonaws.com": [["ec2:RunInstances"]],
    "lambda.amazonaws.com": [["lambda:CreateFunction", "lambda:InvokeFunction"]],
    "cloudformation.amazonaws.com": [["cloudformation:CreateStack"]],
    "codebuild.amazonaws.com": [["codebuild:CreateProject", "codebuild:StartBuild"]],
}
NOISE_SERVICES = ["glue.amazonaws.com", "sagemaker.amazonaws.com", "ecs-tasks.amazonaws.com"]
NOISE_ACTIONS = ["s3:GetObject", "dynamodb:Query", "cloudwatch:PutMetricData", "logs:PutLogEvents",
                 "ec2:DescribeInstances", "sqs:SendMessage", "kms:Decrypt", "sts:GetCallerIdentity"]


def arn_role(name): return f"arn:aws:iam::{ACCOUNT}:role/{name}"


@dataclass
class Case:
    case_id: str
    category: str          # hard_positive | hard_negative | decoy | unresolved_by_design
    recipe: str
    entry_sa: str
    entry_ns: str
    roles: list[dict] = field(default_factory=list)
    sa_role_map: dict[str, str] = field(default_factory=dict)   # sa -> role name (IRSA annotations)
    truth: dict[str, Any] = field(default_factory=dict)
    notes: str = ""


def oidc_trust_stmt(sa, ns, extra_cond=None, deny=False, mfa=False):
    cond = {"StringEquals": {f"{OIDC_HOST}:sub": f"system:serviceaccount:{ns}:{sa}",
                             f"{OIDC_HOST}:aud": AUD}}
    if mfa:
        cond["Bool"] = {"aws:MultiFactorAuthPresent": "true"}
    if extra_cond:
        for op, kv in extra_cond.items():
            cond.setdefault(op, {}).update(kv)
    return {"Effect": "Deny" if deny else "Allow", "Principal": {"Federated": OIDC_PROVIDER_ARN},
            "Action": "sts:AssumeRoleWithWebIdentity", "Condition": cond}


def role(name, trust_stmts, policy_stmts=None, admin=False):
    return {"Arn": arn_role(name), "RoleName": name, "is_admin": admin,
            "AssumeRolePolicyDocument": {"Statement": trust_stmts},
            "policy_documents": [{"Statement": policy_stmts}] if policy_stmts else [],
            "trust_principals": [], "passrole_resources": []}


def svc_trust(service, cond=None):
    st = {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}
    if cond:
        st["Condition"] = cond
    return st


def aws_trust(role_arn, cond=None):
    st = {"Effect": "Allow", "Principal": {"AWS": role_arn}, "Action": "sts:AssumeRole"}
    if cond:
        st["Condition"] = cond
    return st


def allow(action, resource="*", cond=None):
    s = {"Effect": "Allow", "Action": action, "Resource": resource}
    if cond:
        s["Condition"] = cond
    return s


def deny(action, resource="*", cond=None):
    s = {"Effect": "Deny", "Action": action, "Resource": resource}
    if cond:
        s["Condition"] = cond
    return s


def _noise_roles(rng, n, tag):
    """Roles unconnected to the entry point: same 'shape' as real mechanisms
    (some are admin, some accept IRSA-looking trust) but never wired to the
    case's entry ServiceAccount, so they must never appear in a found path."""
    out = []
    for i in range(n):
        nm = f"noise-{tag}-{i}-{rng.randrange(10**6)}"
        kind = rng.choice(["plain", "admin_unreachable", "irsa_other_sa"])
        if kind == "plain":
            out.append(role(nm, [svc_trust(rng.choice(NOISE_SERVICES))],
                            [allow(rng.choice(NOISE_ACTIONS))]))
        elif kind == "admin_unreachable":
            # admin role that nothing in this case can reach (trust excludes the entry chain)
            out.append(role(nm, [svc_trust(rng.choice(NOISE_SERVICES))], [ADMIN_STMT], admin=True))
        else:
            # IRSA-trusted role bound to a DIFFERENT ServiceAccount name, never mapped
            out.append(role(nm, [oidc_trust_stmt(f"unmapped-{nm}", "default")], [ADMIN_STMT], admin=True))
    return out


# ---------------------------------------------------------------------------
# Recipes. Each returns a Case. `rng` drives all naming/randomization so the
# whole generator is reproducible from (seed, index).
# ---------------------------------------------------------------------------

def _base(rng, cid, category, recipe, ns=None):
    ns = ns or rng.choice(["default", "prod", "app-ns", "payments", "ml-team"])
    # Kubernetes names are RFC 1123 subdomains: lowercase alphanumeric and
    # '-' only. Recipe names contain '_' (e.g. "assumerole_chain_2hop"), so
    # that character must not reach a ServiceAccount name.
    sa = f"sa-{recipe.replace('_', '-')}-{rng.randrange(10**6)}"
    return Case(case_id=cid, category=category, recipe=recipe, entry_sa=sa, entry_ns=ns)


def r_direct_admin_valid(rng, cid):
    c = _base(rng, cid, "hard_positive", "direct_admin_valid")
    r = role("target", [oidc_trust_stmt(c.entry_sa, c.entry_ns)], [ADMIN_STMT], admin=True)
    c.roles = [r]; c.sa_role_map = {c.entry_sa: "target"}
    c.truth = {"reachable": True, "confidence": "confirmed", "target": arn_role("target"),
              "mechanism": "irsa_bridge only, valid OIDC trust to an admin role"}
    return c


def r_direct_admin_wrong_subject(rng, cid):
    c = _base(rng, cid, "hard_negative", "direct_admin_wrong_subject")
    other_sa = f"other-{rng.randrange(10**6)}"
    r = role("target", [oidc_trust_stmt(other_sa, c.entry_ns)], [ADMIN_STMT], admin=True)
    c.roles = [r]; c.sa_role_map = {c.entry_sa: "target"}
    c.truth = {"reachable": False, "confidence": None, "target": arn_role("target"),
              "mechanism": "IRSA annotation present but trust policy's sub does not match this SA"}
    return c


def r_direct_admin_mfa_gated(rng, cid):
    c = _base(rng, cid, "hard_negative", "direct_admin_mfa_gated")
    r = role("target", [oidc_trust_stmt(c.entry_sa, c.entry_ns, mfa=True)], [ADMIN_STMT], admin=True)
    c.roles = [r]; c.sa_role_map = {c.entry_sa: "target"}
    c.truth = {"reachable": False, "confidence": None, "target": arn_role("target"),
              "mechanism": "trust requires MFA, which web identity federation can never present"}
    return c


def r_direct_admin_explicit_deny(rng, cid):
    c = _base(rng, cid, "hard_negative", "direct_admin_explicit_deny")
    r = role("target", [oidc_trust_stmt(c.entry_sa, c.entry_ns)],
             [ADMIN_STMT, deny("*", "*")], admin=True)
    c.roles = [r]; c.sa_role_map = {c.entry_sa: "target"}
    c.truth = {"reachable": False, "confidence": None, "target": arn_role("target"),
              "mechanism": "explicit Deny */* makes the role inert despite admin Allow"}
    return c


def r_direct_admin_partial_deny(rng, cid):
    c = _base(rng, cid, "hard_positive", "direct_admin_partial_deny")
    r = role("target", [oidc_trust_stmt(c.entry_sa, c.entry_ns)],
             [ADMIN_STMT, deny("s3:DeleteBucket", "*")], admin=True)
    c.roles = [r]; c.sa_role_map = {c.entry_sa: "target"}
    c.truth = {"reachable": True, "confidence": "confirmed", "target": arn_role("target"),
              "mechanism": "Deny is scoped to one action; role is still admin-labelled overall"}
    return c


def r_direct_admin_ip_condition(rng, cid):
    c = _base(rng, cid, "unresolved_by_design", "direct_admin_ip_condition")
    r = role("target", [oidc_trust_stmt(c.entry_sa, c.entry_ns)],
             [ADMIN_STMT, deny("*", "*", {"IpAddressIfExists": {"aws:SourceIp": "10.0.0.0/8"}})], admin=True)
    c.roles = [r]; c.sa_role_map = {c.entry_sa: "target"}
    c.truth = {"reachable": None, "confidence": "unresolved", "target": arn_role("target"),
              "mechanism": "Deny gated on source IP, not decidable statically"}
    return c


def r_passrole_bare(rng, cid):
    c = _base(rng, cid, "hard_positive", "passrole_bare")
    admin = role("target-admin", [svc_trust("ec2.amazonaws.com")], [ADMIN_STMT], admin=True)
    entry = role("entry", [oidc_trust_stmt(c.entry_sa, c.entry_ns)],
                [allow("iam:PassRole", arn_role("target-admin"))])
    c.roles = [entry, admin]; c.sa_role_map = {c.entry_sa: "entry"}
    c.truth = {"reachable": True, "confidence": "potential", "target": arn_role("target-admin"),
              "mechanism": "bare PassRole, no paired completing action"}
    return c


def r_passrole_paired_confirmed(rng, cid):
    c = _base(rng, cid, "hard_positive", "passrole_paired_confirmed")
    svc, actions = rng.choice(list(PAIRED_ACTIONS.items()))
    admin = role("target-admin", [svc_trust(svc)], [ADMIN_STMT], admin=True)
    stmts = [allow("iam:PassRole", arn_role("target-admin"))] + [allow(a) for a in actions]
    entry = role("entry", [oidc_trust_stmt(c.entry_sa, c.entry_ns)], stmts)
    c.roles = [entry, admin]; c.sa_role_map = {c.entry_sa: "entry"}
    c.truth = {"reachable": True, "confidence": "confirmed", "target": arn_role("target-admin"),
              "mechanism": f"PassRole plus paired action(s) {actions} on {svc}"}
    return c


def r_passrole_wrong_service_condition(rng, cid):
    c = _base(rng, cid, "hard_negative", "passrole_wrong_service_condition")
    admin = role("target-admin", [svc_trust("ec2.amazonaws.com")], [ADMIN_STMT], admin=True)
    stmts = [allow("iam:PassRole", arn_role("target-admin"),
                   {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}),
             allow("ec2:RunInstances")]
    entry = role("entry", [oidc_trust_stmt(c.entry_sa, c.entry_ns)], stmts)
    c.roles = [entry, admin]; c.sa_role_map = {c.entry_sa: "entry"}
    c.truth = {"reachable": False, "confidence": None, "target": arn_role("target-admin"),
              "mechanism": "PassedToService=lambda but target only trusts ec2; grant unusable for this target"}
    return c


def r_passrole_target_untrusted(rng, cid):
    c = _base(rng, cid, "hard_negative", "passrole_target_untrusted")
    other_role = f"arn:aws:iam::{ACCOUNT}:role/someone-else-{rng.randrange(10**6)}"
    admin = role("target-admin", [aws_trust(other_role)], [ADMIN_STMT], admin=True)
    entry = role("entry", [oidc_trust_stmt(c.entry_sa, c.entry_ns)],
                [allow("iam:PassRole", arn_role("target-admin")), allow("ec2:RunInstances")])
    c.roles = [entry, admin]; c.sa_role_map = {c.entry_sa: "entry"}
    c.truth = {"reachable": False, "confidence": None, "target": arn_role("target-admin"),
              "mechanism": "no service can assume the target, so no completing action makes the grant usable"}
    return c


def r_passrole_glob_resource(rng, cid):
    c = _base(rng, cid, "hard_positive", "passrole_glob_resource")
    prefix = f"app-{rng.randrange(10**5)}"
    admin = role(f"{prefix}-admin", [svc_trust("ec2.amazonaws.com")], [ADMIN_STMT], admin=True)
    entry = role("entry", [oidc_trust_stmt(c.entry_sa, c.entry_ns)],
                [allow("iam:PassRole", f"arn:aws:iam::{ACCOUNT}:role/{prefix}-*"), allow("ec2:RunInstances")])
    c.roles = [entry, admin]; c.sa_role_map = {c.entry_sa: "entry"}
    c.truth = {"reachable": True, "confidence": "confirmed", "target": arn_role(f"{prefix}-admin"),
              "mechanism": "PassRole Resource glob covers the target"}
    return c


def r_deny_cancels_passrole(rng, cid):
    c = _base(rng, cid, "hard_negative", "deny_cancels_passrole")
    admin = role("target-admin", [svc_trust("ec2.amazonaws.com")], [ADMIN_STMT], admin=True)
    entry = role("entry", [oidc_trust_stmt(c.entry_sa, c.entry_ns)],
                [allow("iam:PassRole", "*"), allow("ec2:RunInstances"),
                 deny("iam:PassRole", arn_role("target-admin"))])
    c.roles = [entry, admin]; c.sa_role_map = {c.entry_sa: "entry"}
    c.truth = {"reachable": False, "confidence": None, "target": arn_role("target-admin"),
              "mechanism": "specific Deny on PassRole to this exact target cancels the wildcard Allow"}
    return c


def r_assumerole_chain_confirmed(rng, cid, hops=None):
    hops = hops or rng.choice([2, 3])
    c = _base(rng, cid, "hard_positive", f"assumerole_chain_{hops}hop")
    names = [f"hop{i}" for i in range(hops)] + ["target-admin"]
    roles = []
    for i, nm in enumerate(names):
        if nm == "target-admin":
            roles.append(role(nm, [aws_trust(arn_role(names[i - 1]))], [ADMIN_STMT], admin=True))
        elif i == 0:
            roles.append(role(nm, [oidc_trust_stmt(c.entry_sa, c.entry_ns)],
                              [allow("sts:AssumeRole", arn_role(names[i + 1]))]))
        else:
            roles.append(role(nm, [aws_trust(arn_role(names[i - 1]))],
                              [allow("sts:AssumeRole", arn_role(names[i + 1]))]))
    c.roles = roles; c.sa_role_map = {c.entry_sa: names[0]}
    c.truth = {"reachable": True, "confidence": "confirmed", "target": arn_role("target-admin"),
              "mechanism": f"{hops+1}-hop AssumeRole trust chain, all links valid"}
    return c


def r_assumerole_chain_broken(rng, cid):
    hops = rng.choice([2, 3])
    c = _base(rng, cid, "hard_negative", f"assumerole_chain_broken_{hops}hop")
    names = [f"hop{i}" for i in range(hops)] + ["target-admin"]
    break_at = rng.randrange(1, len(names))   # break the trust INTO names[break_at]
    roles = []
    for i, nm in enumerate(names):
        wrong_truster = arn_role(f"someone-else-{rng.randrange(10**6)}") if i == break_at else \
            (arn_role(names[i - 1]) if i > 0 else None)
        if nm == "target-admin":
            roles.append(role(nm, [aws_trust(wrong_truster or arn_role(names[i - 1]))], [ADMIN_STMT], admin=True))
        elif i == 0:
            roles.append(role(nm, [oidc_trust_stmt(c.entry_sa, c.entry_ns)],
                              [allow("sts:AssumeRole", arn_role(names[i + 1]))]))
        else:
            roles.append(role(nm, [aws_trust(wrong_truster or arn_role(names[i - 1]))],
                              [allow("sts:AssumeRole", arn_role(names[i + 1]))] if i + 1 < len(names) else []))
    c.roles = roles; c.sa_role_map = {c.entry_sa: names[0]}
    c.truth = {"reachable": False, "confidence": None, "target": arn_role("target-admin"),
              "mechanism": f"chain broken at hop {break_at}: that role does not trust the previous hop"}
    return c


def r_wildcard_trust_exploitable(rng, cid):
    c = _base(rng, cid, "hard_positive", "wildcard_trust_exploitable")
    wt = {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}
    admin = role("open-admin", [wt], [ADMIN_STMT], admin=True)
    entry = role("entry", [oidc_trust_stmt(c.entry_sa, c.entry_ns)], [allow("sts:AssumeRole")])
    c.roles = [entry, admin]; c.sa_role_map = {c.entry_sa: "entry"}
    c.truth = {"reachable": True, "confidence": "confirmed", "target": arn_role("open-admin"),
              "mechanism": "Principal:* trust, caller has generic sts:AssumeRole permission",
              "expect_exposure_finding": True}
    return c


def r_wildcard_trust_not_exploitable(rng, cid):
    c = _base(rng, cid, "hard_negative", "wildcard_trust_not_exploitable")
    wt = {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}
    admin = role("open-admin", [wt], [ADMIN_STMT], admin=True)
    entry = role("entry", [oidc_trust_stmt(c.entry_sa, c.entry_ns)], [allow("s3:GetObject")])
    c.roles = [entry, admin]; c.sa_role_map = {c.entry_sa: "entry"}
    c.truth = {"reachable": False, "confidence": None, "target": arn_role("open-admin"),
              "mechanism": "Principal:* trust exists but caller has no sts:AssumeRole permission of its own",
              "expect_exposure_finding": True}
    return c


def r_wildcard_trust_conditioned(rng, cid):
    c = _base(rng, cid, "unresolved_by_design", "wildcard_trust_conditioned")
    wt = {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole",
          "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc123xyz"}}}
    admin = role("org-admin", [wt], [ADMIN_STMT], admin=True)
    entry = role("entry", [oidc_trust_stmt(c.entry_sa, c.entry_ns)], [allow("sts:AssumeRole")])
    c.roles = [entry, admin]; c.sa_role_map = {c.entry_sa: "entry"}
    c.truth = {"reachable": None, "confidence": "unresolved", "target": arn_role("org-admin"),
              "mechanism": "wildcard trust gated by org ID, not decidable statically",
              "expect_exposure_finding": True}
    return c


def r_decoy_unreachable_admin(rng, cid):
    """An admin role sits in the graph, and the entry role even shares a
    namespace/naming convention with it, but nothing connects them: no
    trust edge, no PassRole grant, no IRSA mapping. A tool that pattern-
    matches on 'admin role present nearby' should false-positive here;
    CrossGuard should not."""
    c = _base(rng, cid, "decoy", "decoy_unreachable_admin")
    admin = role("nearby-admin", [svc_trust(rng.choice(NOISE_SERVICES))], [ADMIN_STMT], admin=True)
    entry = role("entry", [oidc_trust_stmt(c.entry_sa, c.entry_ns)], [allow(rng.choice(NOISE_ACTIONS))])
    c.roles = [entry, admin]; c.sa_role_map = {c.entry_sa: "entry"}
    c.truth = {"reachable": False, "confidence": None, "target": arn_role("nearby-admin"),
              "mechanism": "admin role present in the graph but no generated edge reaches it"}
    return c


def r_decoy_rbac_only(rng, cid):
    """K8s-side privilege escalation shape (handled by this recipe only at
    the AWS-graph level: no IRSA mapping at all) -- CrossGuard's scope is
    cross-layer, so a same-layer-only setup must yield zero paths."""
    c = _base(rng, cid, "decoy", "decoy_rbac_only_no_irsa")
    c.roles = []
    c.sa_role_map = {}   # no IRSA annotation for this SA at all
    c.truth = {"reachable": False, "confidence": None, "target": None,
              "mechanism": "no IRSA annotation; nothing for the cross-layer analyzer to traverse"}
    return c


RECIPES = [
    r_direct_admin_valid, r_direct_admin_wrong_subject, r_direct_admin_mfa_gated,
    r_direct_admin_explicit_deny, r_direct_admin_partial_deny, r_direct_admin_ip_condition,
    r_passrole_bare, r_passrole_paired_confirmed, r_passrole_wrong_service_condition,
    r_passrole_target_untrusted, r_passrole_glob_resource, r_deny_cancels_passrole,
    r_assumerole_chain_confirmed, r_assumerole_chain_broken,
    r_wildcard_trust_exploitable, r_wildcard_trust_not_exploitable, r_wildcard_trust_conditioned,
    r_decoy_unreachable_admin, r_decoy_rbac_only,
]


def generate(n, seed, split):
    """Deterministic in (n, seed, split) alone: never mutates module state,
    so repeated calls in the same process give identical output."""
    rng = random.Random(f"{seed}-{split}")
    recipes = list(RECIPES)
    cases = []
    for i in range(n):
        if i % len(recipes) == 0:
            rng.shuffle(recipes)
        recipe_fn = recipes[i % len(recipes)]
        c = recipe_fn(rng, f"{split}-{i:05d}-{recipe_fn.__name__}")
        c.roles.extend(_noise_roles(rng, rng.choice([0, 1, 1, 2, 3]), c.case_id))
        cases.append(c)
    return cases


def to_jsonl(cases, path):
    with open(path, "w") as f:
        for c in cases:
            f.write(json.dumps({
                "case_id": c.case_id, "category": c.category, "recipe": c.recipe,
                "entry_sa": c.entry_sa, "entry_ns": c.entry_ns, "roles": c.roles,
                "sa_role_map": c.sa_role_map, "truth": c.truth, "notes": c.notes,
            }) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=30001)
    ap.add_argument("--split", choices=["dev", "heldout"], required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    cases = generate(args.n, args.seed, args.split)
    to_jsonl(cases, args.out)
    from collections import Counter
    print(f"{len(cases)} cases -> {args.out}")
    print("by category:", Counter(c.category for c in cases))
    print("by recipe:  ", Counter(c.recipe.rsplit('_', 1)[0] if c.recipe[-1].isdigit() else c.recipe for c in cases))


if __name__ == "__main__":
    main()
