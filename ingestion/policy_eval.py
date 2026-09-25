"""
ingestion/policy_eval.py

Static policy evaluation used by the graph builder. It closes the
limitations documented as L1 (PassRole pairing), L4 (Deny / Condition
blindness) and L7 (wildcard trust), and adds a check the earlier version
lacked entirely: whether an IRSA-annotated role's trust policy actually
permits the ServiceAccount to assume it via web identity.

Design rule: every check is THREE-VALUED (true / false / unknown).
"unknown" means the answer depends on runtime context we cannot see
statically (source IP, tags, org membership, policy variables, unsupported
operators). Unknown never silently becomes true or false: it keeps the
edge and marks it as "unresolved" so the report can count it separately.

This is still a static abstraction. It does NOT implement full AWS policy
evaluation logic: no SCPs, no permission boundaries, no session policies,
no resource-based policies other than role trust policies. See Table II of
the paper for the full list of non-goals.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Any

from ingestion.policy_utils import statements

TRUE, FALSE, UNKNOWN = "true", "false", "unknown"

# Sentinels for context values.
ABSENT = object()    # key is known to be absent from the request context
MISSING = object()   # key is not in our context at all (=> unknown)

CONF_CONFIRMED, CONF_POTENTIAL, CONF_UNRESOLVED = "confirmed", "potential", "unresolved"
CONF_RANK = {CONF_CONFIRMED: 3, CONF_POTENTIAL: 2, CONF_UNRESOLVED: 1}


@dataclass(frozen=True)
class EvalConfig:
    """Switches for each evaluation feature. LEGACY reproduces the
    behaviour of the original tool (used for before/after comparison)."""
    deny: bool = True                      # explicit-Deny handling
    conditions: bool = True                # Condition-block evaluation
    passrole_pairing: bool = True          # paired-action check (L1)
    wildcard_trust: bool = True            # Principal:"*" modelling (L7)
    irsa_trust: str = "strict"             # off | annotate | strict
    passrole_target_trust: str = "strict"  # off | annotate | strict
    oidc_provider_arn: str | None = None   # if set, must match exactly
    audience: str = "sts.amazonaws.com"

    def as_dict(self) -> dict:
        return dict(self.__dict__)


LEGACY = EvalConfig(
    deny=False, conditions=False, passrole_pairing=False,
    wildcard_trust=False, irsa_trust="off", passrole_target_trust="off",
)
# ANNOTATE keeps every edge and only labels it (useful to audit what STRICT drops).
ANNOTATE = EvalConfig(irsa_trust="annotate", passrole_target_trust="annotate")
# STRICT (the default) suppresses edges that are DEFINITELY unusable under the
# analyzed abstraction -- e.g. an IRSA role whose trust policy has no OIDC
# principal, or a PassRole target no service can assume. Every suppression is
# recorded in G.graph["suppressed_edges"] with its reason.
STRICT = EvalConfig()
DEFAULT = STRICT


def _as_list(v: Any) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _and(vals: list[str]) -> str:
    if FALSE in vals:
        return FALSE
    if UNKNOWN in vals:
        return UNKNOWN
    return TRUE


def _or(vals: list[str]) -> str:
    if TRUE in vals:
        return TRUE
    if UNKNOWN in vals:
        return UNKNOWN
    return FALSE


# ---------------------------------------------------------------------------
# Condition evaluation
# ---------------------------------------------------------------------------

_POSITIVE = {
    "stringequals": ("eq", False), "stringequalsignorecase": ("eqi", False),
    "stringlike": ("like", False), "arnequals": ("like", False),
    "arnlike": ("like", False), "bool": ("bool", False),
}
_NEGATED = {
    "stringnotequals": ("eq", True), "stringnotequalsignorecase": ("eqi", True),
    "stringnotlike": ("like", True), "arnnotequals": ("like", True),
    "arnnotlike": ("like", True),
}
_SUPPORTED = {**_POSITIVE, **_NEGATED}


def _lookup(ctx: dict, key: str):
    k = key.lower()
    if k in ctx:
        return ctx[k]
    # OIDC provider-scoped keys look like "oidc.eks.<region>.amazonaws.com/id/<ID>:sub"
    if k.endswith(":sub") or k.endswith(":aud"):
        if not k.startswith("aws:") and ("oidc" in k or "/" in k):
            return ctx.get("oidc:" + k[-3:], MISSING)
    return MISSING


def _match(kind: str, ctx_val: str, policy_val: str) -> bool:
    cv, pv = str(ctx_val), str(policy_val)
    if kind == "eq":
        return cv == pv
    if kind == "eqi":
        return cv.lower() == pv.lower()
    if kind == "like":
        return fnmatch.fnmatchcase(cv, pv)
    if kind == "bool":
        return cv.lower() == pv.lower()
    return False


def evaluate_condition(condition: dict | None, ctx: dict) -> str:
    """Three-valued evaluation of a Condition block against a context.

    ctx keys must be lower-case. Values: str, list[str], ABSENT.
    Unsupported operators (numeric, IP, date, ForAnyValue/ForAllValues set
    operators, policy variables) evaluate to UNKNOWN.
    """
    if not condition:
        return TRUE
    results: list[str] = []
    for op, kv in condition.items():
        if ":" in op:                      # ForAnyValue:/ForAllValues: set operators
            results.append(UNKNOWN)
            continue
        if_exists = op.lower().endswith("ifexists")
        base = op[:-8] if if_exists else op
        base_l = base.lower()
        for key, raw_vals in (kv or {}).items():
            vals = _as_list(raw_vals)
            val = _lookup(ctx, key)
            if base_l == "null":
                if val is MISSING:
                    results.append(UNKNOWN)
                else:
                    want_null = str(vals[0]).lower() == "true" if vals else True
                    results.append(TRUE if (val is ABSENT) == want_null else FALSE)
                continue
            if val is MISSING:
                results.append(UNKNOWN)
                continue
            if base_l not in _SUPPORTED:
                results.append(UNKNOWN)
                continue
            if val is ABSENT:
                if if_exists or base_l in _NEGATED:
                    results.append(TRUE)
                else:
                    results.append(FALSE)
                continue
            if any("${" in str(v) for v in vals):
                results.append(UNKNOWN)
                continue
            kind, negated = _SUPPORTED[base_l]
            hit = any(_match(kind, cv, pv) for cv in _as_list(val) for pv in vals)
            results.append(TRUE if (not hit if negated else hit) else FALSE)
    return _and(results) if results else TRUE


# ---------------------------------------------------------------------------
# Statement matching and decisions
# ---------------------------------------------------------------------------

def _glob(pattern: str, value: str, *, ci: bool) -> bool:
    if ci:
        return fnmatch.fnmatchcase(value.lower(), pattern.lower())
    return fnmatch.fnmatchcase(value, pattern)


def _action_hit(stmt: dict, action: str) -> bool:
    if "Action" in stmt:
        return any(_glob(a, action, ci=True) for a in _as_list(stmt["Action"]))
    if "NotAction" in stmt:
        return not any(_glob(a, action, ci=True) for a in _as_list(stmt["NotAction"]))
    return False


def _resource_hit(stmt: dict, resource: str | None) -> str:
    if "Resource" in stmt:
        pats = _as_list(stmt["Resource"])
        if resource is None:                       # "any / unspecified resource"
            return TRUE if "*" in pats else UNKNOWN
        return TRUE if any(_glob(p, resource, ci=False) for p in pats) else FALSE
    if "NotResource" in stmt:
        if resource is None:
            return UNKNOWN
        pats = _as_list(stmt["NotResource"])
        return FALSE if any(_glob(p, resource, ci=False) for p in pats) else TRUE
    return TRUE   # trust-policy statements have no Resource element


def statement_match(stmt: dict, action: str, resource: str | None, ctx: dict) -> str:
    if not _action_hit(stmt, action):
        return FALSE
    return _and([_resource_hit(stmt, resource),
                 evaluate_condition(stmt.get("Condition"), ctx)])


def decide(stmts: list[dict], action: str, resource: str | None = None,
           ctx: dict | None = None) -> str:
    """Return 'allow' | 'allow_unresolved' | 'deny' | 'implicit_deny'.

    Explicit Deny beats Allow. A Deny whose condition is undecidable turns
    an otherwise-clear allow into 'allow_unresolved'.
    """
    ctx = ctx or {}
    allow_states, deny_states = [], []
    for s in stmts:
        eff = s.get("Effect")
        if eff not in ("Allow", "Deny"):
            continue
        state = statement_match(s, action, resource, ctx)
        (allow_states if eff == "Allow" else deny_states).append(state)
    if TRUE in deny_states:
        return "deny"
    if TRUE in allow_states and UNKNOWN not in deny_states:
        return "allow"
    if TRUE in allow_states or UNKNOWN in allow_states:
        return "allow_unresolved"
    return "implicit_deny"


def entity_statements(entity: dict) -> list[dict]:
    out: list[dict] = []
    for doc in entity.get("policy_documents", []) or []:
        out.extend(statements(doc))
    return out


def has_raw_policies(entity: dict) -> bool:
    return bool(entity.get("policy_documents")) or "AssumeRolePolicyDocument" in entity


# ---------------------------------------------------------------------------
# Admin sink status (Deny-aware)
# ---------------------------------------------------------------------------

def admin_status(entity: dict, cfg: EvalConfig) -> dict:
    """Refine the ingestion-time is_admin flag using explicit Deny.

    status:
      none        -- not admin under the heuristic
      full        -- Allow */* and no applicable Deny
      full_partial_deny -- admin, but specific actions are denied (annotated,
                     NOT downgraded: the role is still administrator-like)
      inert       -- an unconditional Deny covering all actions and resources
      unresolved  -- a Deny covering everything whose Condition is undecidable
    """
    base = bool(entity.get("is_admin", False))
    if not base:
        return {"is_admin": False, "status": "none", "partial_denies": []}
    if not cfg.deny:
        return {"is_admin": True, "status": "full", "partial_denies": []}

    inert, unresolved, partial = False, False, []
    for s in entity_statements(entity):
        if s.get("Effect") != "Deny":
            continue
        acts = _as_list(s.get("Action"))
        covers_all_actions = "NotAction" not in s and any(a in ("*", "*:*") for a in acts)
        covers_all_res = "NotResource" not in s and "*" in _as_list(s.get("Resource"))
        cond = evaluate_condition(s.get("Condition"), {})
        if covers_all_actions and covers_all_res:
            if cond == TRUE:
                inert = True
            elif cond == UNKNOWN:
                unresolved = True
        elif cond != FALSE:
            partial.append({"actions": acts or ["<NotAction>"], "condition": cond})
    if inert:
        return {"is_admin": False, "status": "inert", "partial_denies": partial}
    if unresolved:
        return {"is_admin": True, "status": "unresolved", "partial_denies": partial}
    return {"is_admin": True,
            "status": "full_partial_deny" if partial else "full",
            "partial_denies": partial}


# ---------------------------------------------------------------------------
# Trust policy analysis
# ---------------------------------------------------------------------------

def _principal_items(stmt: dict) -> list[tuple[str, str]]:
    p = stmt.get("Principal", {})
    if isinstance(p, str):
        return [("AWS", p)]
    items = []
    for ptype, vals in (p or {}).items():
        for v in _as_list(vals):
            items.append((ptype, v))
    return items


def _grants_action(stmt: dict, action: str) -> bool:
    return _action_hit(stmt, action)


def irsa_trust_status(trust_doc: dict | None, namespace: str, sa_name: str,
                      cfg: EvalConfig) -> tuple[str, str]:
    """Would AssumeRoleWithWebIdentity succeed for this ServiceAccount?

    Returns (status, reason); status in valid | invalid | unresolved |
    not_evaluated. We model the EKS OIDC token claims we know statically:
    sub = system:serviceaccount:<ns>:<name>, aud = sts.amazonaws.com, and
    no MFA context. The cluster's OIDC issuer is checked only if
    cfg.oidc_provider_arn is set; otherwise any OIDC-provider Federated
    principal is accepted (we do not know the issuer offline).
    """
    if not trust_doc:
        return "not_evaluated", "role has no trust policy document in ingested data"
    ctx = {
        "oidc:sub": f"system:serviceaccount:{namespace}:{sa_name}",
        "oidc:aud": cfg.audience,
        "aws:multifactorauthpresent": ABSENT,
    }
    allows, denies, candidates = [], [], 0
    for s in statements(trust_doc):
        if not _grants_action(s, "sts:AssumeRoleWithWebIdentity"):
            continue
        fed = [v for t, v in _principal_items(s) if t == "Federated"]
        if cfg.oidc_provider_arn:
            ok_principal = cfg.oidc_provider_arn in fed
        else:
            ok_principal = any("oidc-provider/" in v or "oidc" in v.lower() for v in fed)
        if s.get("Effect") == "Deny":
            denies.append(evaluate_condition(s.get("Condition"), ctx))
            continue
        if s.get("Effect") != "Allow" or not ok_principal:
            continue
        candidates += 1
        allows.append(evaluate_condition(s.get("Condition"), ctx))
    if TRUE in denies:
        return "invalid", "explicit Deny in trust policy matches this ServiceAccount"
    if candidates == 0:
        return "invalid", ("trust policy has no Allow statement granting "
                           "sts:AssumeRoleWithWebIdentity to an OIDC federated principal")
    if TRUE in allows and UNKNOWN not in denies:
        return "valid", "trust policy permits this ServiceAccount subject"
    if TRUE in allows or UNKNOWN in allows:
        return "unresolved", "trust conditions depend on context not known statically"
    return "invalid", "trust conditions (sub/aud/MFA) do not match this ServiceAccount"


def wildcard_trust_status(trust_doc: dict | None) -> str | None:
    """'unrestricted' | 'conditioned' | None for Principal:"*" trust."""
    best = None
    for s in statements(trust_doc or {}):
        if s.get("Effect") != "Allow":
            continue
        if not (_grants_action(s, "sts:AssumeRole")):
            continue
        if not any(v == "*" for _, v in _principal_items(s)):
            continue
        cond = evaluate_condition(s.get("Condition"), {})
        if cond == TRUE:
            return "unrestricted"
        if cond == UNKNOWN:
            best = "conditioned"
    return best


def named_principal_trust(trust_doc: dict, cfg: EvalConfig) -> list[dict]:
    """AWS-principal ARNs allowed to sts:AssumeRole, with condition state."""
    denied = set()
    for s in statements(trust_doc):
        if s.get("Effect") == "Deny" and _grants_action(s, "sts:AssumeRole"):
            if evaluate_condition(s.get("Condition"), {}) == TRUE:
                denied.update(v for t, v in _principal_items(s) if t == "AWS")
    out = []
    for s in statements(trust_doc):
        if s.get("Effect") != "Allow" or not _grants_action(s, "sts:AssumeRole"):
            continue
        cond = evaluate_condition(s.get("Condition"), {}) if cfg.conditions else TRUE
        if cond == FALSE:
            continue
        for t, v in _principal_items(s):
            if t == "AWS" and v != "*" and v not in denied:
                out.append({"principal": v, "condition": cond})
    return out


def service_can_assume(trust_doc: dict | None, service: str) -> str:
    """Can AWS service `service` assume the role? true/false/unknown."""
    if not trust_doc:
        return UNKNOWN
    ctx = {"aws:multifactorauthpresent": ABSENT}
    states = []
    for s in statements(trust_doc):
        if s.get("Effect") != "Allow" or not _grants_action(s, "sts:AssumeRole"):
            continue
        svc = [v for t, v in _principal_items(s) if t == "Service"]
        if service in svc:
            states.append(evaluate_condition(s.get("Condition"), ctx))
    return _or(states) if states else FALSE


def trusted_services(trust_doc: dict | None) -> list[str]:
    out = []
    for s in statements(trust_doc or {}):
        if s.get("Effect") == "Allow":
            out.extend(v for t, v in _principal_items(s) if t == "Service")
    return sorted(set(out))


# ---------------------------------------------------------------------------
# PassRole pairing (L1)
# ---------------------------------------------------------------------------

# For a bare iam:PassRole to be exploitable, the caller must also hold an
# action that hands the passed role to a service the caller can drive.
# ASSEMBLED FROM PUBLISHED TECHNIQUE LISTS (Rhino Security Labs [21] and the
# PMapper catalog). Each entry is an alternative set of actions; ALL actions
# in one set are required. VERIFY EACH ENTRY AGAINST THE SOURCES BEFORE
# CITING THIS TABLE AS COMPLETE -- it is a working catalog, not an oracle.
PAIRED_ACTION_CATALOG: dict[str, list[list[str]]] = {
    "lambda.amazonaws.com": [
        ["lambda:CreateFunction", "lambda:InvokeFunction"],
        ["lambda:CreateFunction", "lambda:CreateEventSourceMapping"],
        ["lambda:UpdateFunctionConfiguration", "lambda:InvokeFunction"],
    ],
    "ec2.amazonaws.com": [["ec2:RunInstances"]],
    "cloudformation.amazonaws.com": [["cloudformation:CreateStack"]],
    "glue.amazonaws.com": [["glue:CreateDevEndpoint"], ["glue:UpdateDevEndpoint"]],
    "sagemaker.amazonaws.com": [["sagemaker:CreateNotebookInstance"],
                                ["sagemaker:CreateProcessingJob"],
                                ["sagemaker:CreateTrainingJob"]],
    "ecs-tasks.amazonaws.com": [["ecs:RegisterTaskDefinition", "ecs:RunTask"]],
    "codebuild.amazonaws.com": [["codebuild:CreateProject", "codebuild:StartBuild"]],
    "datapipeline.amazonaws.com": [["datapipeline:CreatePipeline",
                                    "datapipeline:PutPipelineDefinition",
                                    "datapipeline:ActivatePipeline"]],
}


def passrole_analysis(source_stmts: list[dict], target_arn: str,
                      target_trust: dict | None, cfg: EvalConfig) -> dict:
    """Classify a PassRole grant from source onto target.

    Returns:
      decision      allow | allow_unresolved | deny | implicit_deny
      confidence    confirmed | potential | unresolved
      services      services the grant covers AND the target trusts
      reason        short human-readable explanation
      target_assumable_by_service  bool | None
    """
    tsvcs = trusted_services(target_trust)
    covered, covered_unresolved = [], []
    for svc in tsvcs:
        d = decide(source_stmts, "iam:PassRole", target_arn,
                   {"iam:passedtoservice": svc})
        if d == "allow":
            covered.append(svc)
        elif d == "allow_unresolved":
            covered_unresolved.append(svc)

    # Decision independent of service (used when target trust lists no service)
    d_any = decide(source_stmts, "iam:PassRole", target_arn, {})
    if d_any == "deny" and not covered and not covered_unresolved:
        return {"decision": "deny", "confidence": CONF_UNRESOLVED, "services": [],
                "reason": "explicit Deny on iam:PassRole", "target_assumable_by_service": None}
    if d_any == "implicit_deny" and not covered and not covered_unresolved:
        return {"decision": "implicit_deny", "confidence": CONF_UNRESOLVED, "services": [],
                "reason": "no Allow matches iam:PassRole on this target", "target_assumable_by_service": None}

    # Which of the covered services can actually assume the target (trust conditions)?
    usable = [s for s in covered if service_can_assume(target_trust, s) != FALSE]
    usable_unres = [s for s in covered_unresolved if service_can_assume(target_trust, s) != FALSE]
    target_ok = bool(usable or usable_unres)

    if not cfg.passrole_pairing:
        return {"decision": d_any, "confidence": CONF_POTENTIAL, "services": usable,
                "reason": "pairing check disabled", "target_assumable_by_service": target_ok}

    if not (covered or covered_unresolved) or not target_ok:
        reason = ("target role trust policy lists no service that can assume it under "
                  "this grant's PassedToService condition")
        return {"decision": d_any, "confidence": CONF_POTENTIAL, "services": [],
                "reason": reason, "target_assumable_by_service": False}

    # Paired-action check for each usable service.
    confirmed_via = []
    for svc in usable:
        for action_set in PAIRED_ACTION_CATALOG.get(svc, []):
            if all(decide(source_stmts, a, None, {}) == "allow" for a in action_set):
                confirmed_via.append({"service": svc, "actions": action_set})
                break
    if confirmed_via:
        return {"decision": "allow", "confidence": CONF_CONFIRMED,
                "services": [c["service"] for c in confirmed_via],
                "paired": confirmed_via,
                "reason": "PassRole plus a paired completing action on a trusted service",
                "target_assumable_by_service": True}
    if usable_unres and not usable:
        return {"decision": "allow_unresolved", "confidence": CONF_UNRESOLVED,
                "services": usable_unres,
                "reason": "PassRole condition undecidable statically",
                "target_assumable_by_service": True}
    return {"decision": d_any, "confidence": CONF_POTENTIAL, "services": usable,
            "reason": "bare PassRole: no paired completing action granted",
            "target_assumable_by_service": True}
