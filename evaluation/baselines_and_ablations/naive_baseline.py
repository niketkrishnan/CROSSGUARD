"""
evaluation/baselines_and_ablations/naive_baseline.py

A deliberately trivial baseline: flag any ServiceAccount whose IRSA
annotation points at a role that is admin-labeled (is_admin=True at
ingestion time, i.e. AdministratorAccess attached or an inline Action:*/
Resource:* statement present) -- full stop. No Deny handling, no Condition
evaluation, no IRSA-trust checking, no PassRole reasoning, no AssumeRole
chain-following, no wildcard-trust modelling. This is what "grep for an
IRSA annotation next to an admin policy" looks like as code -- the kind of
check a team could write in an afternoon without any graph model at all.

Purpose: measure what CrossGuard's cross-layer graph, Deny/Condition
evaluation, IRSA-trust checking and PassRole pairing actually buy over the
simplest thing that could possibly work, on the SAME case sets already
validated elsewhere in this evaluation (sections 10 and 11 of
POLICY_SEMANTICS_EVALUATION.md). This is not a comparison against another
published tool (see external_tool_attempts.md for why PMapper/Cloudsplaining
comparisons already exist in the original paper and why IAM-Deescalate/
IAMPERE were not added here) -- it is a lower bound: any tool claiming
value over "IRSA annotation + admin role present" should beat this.
"""

from __future__ import annotations


def naive_flags(case: dict) -> bool:
    """True if the entry ServiceAccount's mapped role is admin-labeled,
    with NO other reasoning at all -- the naive baseline's entire logic."""
    role_name = case["sa_role_map"].get(case["entry_sa"])
    if role_name is None:
        return False
    role = next((r for r in case["roles"] if r["RoleName"] == role_name), None)
    if role is None:
        return False
    return bool(role.get("is_admin", False))
