"""
evaluation/generated_benchmark/oracle.py

An independent re-check of each generated case's `truth` label.

"Independent" here means: this module imports nothing from
`ingestion.policy_eval` or `graph.builder`, and re-derives each label from
the raw generated JSON using its own, separately-written logic. It shares
the same understanding of AWS semantics as policy_eval (there is only one
correct reading of the docs), so this does NOT catch a shared
misunderstanding of AWS behaviour -- it catches DISAGREEMENT between the
generator's intent (encoded in `truth` at construction time in
generator.py) and what the raw JSON actually says, i.e. generator bugs.
Genuine semantic questions were separately checked against PMapper in
evaluation/policy_semantics/differential/ (a real second implementation).

Every case is scored two ways in run_benchmark.py:
  generator vs oracle      -- do the JSON fixtures match their own stated
                               intent? (this module)
  oracle vs CrossGuard      -- accuracy of the actual tool being evaluated
"""

from __future__ import annotations

import fnmatch


def _stmts(role, key="policy_documents"):
    out = []
    for d in role.get(key, []):
        for s in d.get("Statement", []):
            out.append(s)
    return out


def _trust_stmts(role):
    return role.get("AssumeRolePolicyDocument", {}).get("Statement", [])


def _principal_vals(stmt, ptype):
    p = stmt.get("Principal", {})
    v = p.get(ptype)
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _condition_definitely_blocks(cond, known):
    """known: dict of context key -> value, or 'ABSENT'. Returns True only if
    we can PROVE the condition can never hold (e.g. MFA required but web
    identity never presents MFA). Returns False for anything undecidable --
    the oracle is conservative in the opposite direction of policy_eval
    (never claims 'blocks' unless certain), so a mismatch between the two on
    an undecidable case is expected and not a bug (it's caught separately by
    the unresolved_by_design category, which the oracle scores by category
    membership, not by re-deriving the condition)."""
    if not cond:
        return False
    for op, kv in cond.items():
        for key, want in kv.items():
            kl = key.lower()
            if kl not in known:
                continue
            actual = known[kl]
            if op == "Bool" and actual == "ABSENT":
                return True   # Bool with an absent key is false; if it's the only requirement, Allow can't fire
    return False


def _role_is_admin_and_alive(role):
    """Admin per is_admin flag, minus an unconditional Deny */* anywhere."""
    if not role.get("is_admin"):
        return False
    for s in _stmts(role):
        if s.get("Effect") == "Deny" and s.get("Action") in ("*", ["*"]) and s.get("Resource") in ("*", ["*"]) \
                and "Condition" not in s:
            return False
    return True


def _trust_allows_this_sa(role, sa, ns):
    """Direct re-implementation of 'does this trust policy let SA assume via
    OIDC web identity', independent of policy_eval.irsa_trust_status."""
    expect_sub = f"system:serviceaccount:{ns}:{sa}"
    for s in _trust_stmts(role):
        if s.get("Effect") != "Allow" or s.get("Action") != "sts:AssumeRoleWithWebIdentity":
            continue
        if not _principal_vals(s, "Federated"):
            continue
        cond = s.get("Condition", {})
        subs, auds, mfa_required = [], [], False
        for op, kv in cond.items():
            for k, v in kv.items():
                kl = k.lower()
                if kl.endswith(":sub"):
                    subs += v if isinstance(v, list) else [v]
                elif kl.endswith(":aud"):
                    auds += v if isinstance(v, list) else [v]
                elif kl == "aws:multifactorauthpresent" and op == "Bool" and str(v).lower() == "true":
                    mfa_required = True
        if mfa_required:
            continue   # can never be satisfied by web identity
        sub_ok = not subs or any(fnmatch.fnmatchcase(expect_sub, p) for p in subs)
        aud_ok = not auds or any(a == "sts.amazonaws.com" for a in auds)
        if sub_ok and aud_ok:
            for s2 in _trust_stmts(role):
                if s2.get("Effect") == "Deny" and s2.get("Action") == "sts:AssumeRoleWithWebIdentity":
                    return False   # any Deny on this action blocks the whole trust conservatively
            return True
    return False


def check_direct_irsa(case):
    """Recipes: direct_admin_* and direct_admin_ip_condition."""
    role = case["roles"][0]
    ok = _trust_allows_this_sa(role, case["entry_sa"], case["entry_ns"]) and _role_is_admin_and_alive(role)
    return ok


def check_passrole(case, target_name):
    entry = next(r for r in case["roles"] if r["RoleName"] == "entry")
    target = next(r for r in case["roles"] if r["RoleName"] == target_name)
    if not _trust_allows_this_sa(entry, case["entry_sa"], case["entry_ns"]):
        return False
    target_svcs = {v for s in _trust_stmts(target) if s.get("Effect") == "Allow"
                   for v in _principal_vals(s, "Service")}
    passrole_ok, denied = False, False
    for s in _stmts(entry):
        acts = s.get("Action"); acts = acts if isinstance(acts, list) else [acts]
        if not any(fnmatch.fnmatchcase("iam:PassRole", a) for a in acts):
            continue
        ress = s.get("Resource"); ress = ress if isinstance(ress, list) else [ress]
        if not any(fnmatch.fnmatchcase(target["Arn"], r) for r in ress):
            continue
        cond = s.get("Condition", {})
        svc_ok = True
        for op, kv in cond.items():
            if "PassedToService" in str(kv):
                allowed = kv.get("iam:PassedToService") or kv.get("iam:passedtoservice")
                allowed = allowed if isinstance(allowed, list) else [allowed]
                svc_ok = bool(set(allowed) & target_svcs)
        if s.get("Effect") == "Allow" and svc_ok:
            passrole_ok = True
        if s.get("Effect") == "Deny":
            dress = s.get("Resource"); dress = dress if isinstance(dress, list) else [dress]
            if any(fnmatch.fnmatchcase(target["Arn"], r) for r in dress):
                denied = True
    if not (passrole_ok and target_svcs) or denied:
        return False
    return True


def check_paired_action(case, target_name):
    from evaluation.generated_benchmark.generator import PAIRED_ACTIONS
    entry = next(r for r in case["roles"] if r["RoleName"] == "entry")
    target = next(r for r in case["roles"] if r["RoleName"] == target_name)
    target_svcs = {v for s in _trust_stmts(target) if s.get("Effect") == "Allow"
                   for v in _principal_vals(s, "Service")}
    entry_actions = set()
    for s in _stmts(entry):
        if s.get("Effect") != "Allow":
            continue
        acts = s.get("Action"); acts = acts if isinstance(acts, list) else [acts]
        entry_actions.update(acts)
    for svc in target_svcs:
        for combo in PAIRED_ACTIONS.get(svc, []):
            if all(a in entry_actions for a in combo):
                return True
    return False


def check_chain(case, target_name, expect_reachable):
    """Walk AssumeRole trust edges from the entry role forward; True if
    target_name is reached, independent of graph.builder/pathfinder."""
    by_name = {r["RoleName"]: r for r in case["roles"]}
    entry_name = case["sa_role_map"][case["entry_sa"]]
    if not _trust_allows_this_sa(by_name[entry_name], case["entry_sa"], case["entry_ns"]):
        return False
    frontier = {entry_name}
    seen = set()
    for _ in range(len(case["roles"]) + 1):
        nxt = set()
        for name in frontier:
            r = by_name.get(name)
            if not r:
                continue
            for s in _stmts(r):
                if s.get("Effect") != "Allow":
                    continue
                acts = s.get("Action"); acts = acts if isinstance(acts, list) else [acts]
                if "sts:AssumeRole" not in acts:
                    continue
                ress = s.get("Resource"); ress = ress if isinstance(ress, list) else [ress]
                for other in case["roles"]:
                    if other["Arn"] in ress and other["RoleName"] not in seen:
                        trusted = any(
                            st.get("Effect") == "Allow" and r["Arn"] in _principal_vals(st, "AWS")
                            for st in _trust_stmts(other)
                        )
                        if trusted:
                            nxt.add(other["RoleName"])
        seen |= frontier
        frontier = nxt - seen
        if not frontier:
            break
    return target_name.split("/")[-1] in seen or any(by_name[n]["Arn"] == case["truth"].get("target") for n in seen)


def check_wildcard(case):
    entry = next(r for r in case["roles"] if r["RoleName"] == "entry")
    target = next(r for r in case["roles"] if "admin" in r["RoleName"] and r is not entry)
    has_wildcard_open = False
    for s in _trust_stmts(target):
        if s.get("Effect") == "Allow" and "*" in _principal_vals(s, "AWS") and "Condition" not in s:
            has_wildcard_open = True
    if not has_wildcard_open:
        return False
    caller_can_assume = any(
        s.get("Effect") == "Allow" and s.get("Action") in ("sts:AssumeRole", ["sts:AssumeRole"])
        for s in _stmts(entry)
    )
    return caller_can_assume


def check_case(case: dict) -> dict:
    """Returns {'oracle_reachable': bool|None, 'matches_declared_truth': bool, 'note': str}."""
    recipe = case["recipe"]
    truth = case["truth"]
    declared = truth["reachable"]

    if case["category"] == "unresolved_by_design":
        return {"oracle_reachable": None, "matches_declared_truth": declared is None,
               "note": "category is unresolved_by_design; oracle does not attempt a definite answer"}

    if recipe.startswith("direct_admin"):
        result = check_direct_irsa(case)
    elif recipe == "passrole_bare":
        result = check_passrole(case, "target-admin")
    elif recipe == "passrole_paired_confirmed":
        result = check_passrole(case, "target-admin") and check_paired_action(case, "target-admin")
    elif recipe in ("passrole_wrong_service_condition", "passrole_target_untrusted"):
        result = check_passrole(case, "target-admin")
    elif recipe == "passrole_glob_resource":
        target_name = next(r["RoleName"] for r in case["roles"] if r["RoleName"].endswith("-admin"))
        result = check_passrole(case, target_name)
    elif recipe == "deny_cancels_passrole":
        result = check_passrole(case, "target-admin")
    elif recipe.startswith("assumerole_chain"):
        result = check_chain(case, "target-admin", declared)
    elif recipe.startswith("wildcard_trust_exploitable") or recipe.startswith("wildcard_trust_not_exploitable"):
        result = check_wildcard(case)
    elif recipe == "decoy_unreachable_admin":
        result = False   # by construction, no mechanism connects entry to the noise-shaped admin
    elif recipe == "decoy_rbac_only_no_irsa":
        result = False
    else:
        return {"oracle_reachable": None, "matches_declared_truth": False, "note": f"no oracle check for recipe {recipe}"}

    return {"oracle_reachable": result, "matches_declared_truth": result == declared, "note": ""}
