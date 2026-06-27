"""
ingestion/policy_utils.py

Shared helpers for parsing AWS IAM policy documents (managed, inline, and
trust policies). Kept separate from aws_ingestion.py so the parsing logic
is independently testable and reusable by the graph builder later.

IAM policy documents look like:

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "iam:PassRole",          # str OR list[str]
      "Resource": "*"                     # str OR list[str]
    }
  ]
}

Trust policies (AssumeRolePolicyDocument) have the same shape but the
Principal field is what matters:

{
  "Effect": "Allow",
  "Principal": {"AWS": "arn:aws:iam::123456789012:role/Foo"},   # or "Service": "ec2.amazonaws.com"
  "Action": "sts:AssumeRole"
}
"""

from __future__ import annotations

import fnmatch
from typing import Any, Iterable


ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def _as_list(value: Any) -> list:
    """IAM lets Action/Resource/Principal be a single string or a list.
    Normalize to a list so callers don't need to check both cases."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def statements(policy_document: dict) -> list[dict]:
    """Return the list of statements in a policy document, normalized."""
    if not policy_document:
        return []
    return _as_list(policy_document.get("Statement"))


def action_matches(action_pattern: str, target_action: str) -> bool:
    """IAM actions support trailing/leading wildcards, e.g. 'iam:*',
    's3:Get*', or just '*'. Use fnmatch for glob-style matching, but first
    normalize case since IAM action names are case-insensitive."""
    return fnmatch.fnmatch(target_action.lower(), action_pattern.lower())


def statement_grants_action(statement: dict, action: str) -> bool:
    """Does this single Allow statement grant the given action (e.g.
    'iam:PassRole')? Deny statements are ignored here -- full Allow/Deny
    resolution across an entire policy set is out of scope for this
    research tool; we flag potential grants conservatively."""
    if statement.get("Effect") != "Allow":
        return False
    actions = _as_list(statement.get("Action"))
    return any(action_matches(a, action) for a in actions)


def policy_grants_action(policy_document: dict, action: str) -> bool:
    """Does ANY Allow statement in this policy document grant `action`?"""
    return any(statement_grants_action(s, action) for s in statements(policy_document))


def policy_grants_full_admin(policy_document: dict) -> bool:
    """Heuristic for 'this policy is effectively AdministratorAccess':
    an Allow statement with Action '*' and Resource '*'."""
    for s in statements(policy_document):
        if s.get("Effect") != "Allow":
            continue
        actions = _as_list(s.get("Action"))
        resources = _as_list(s.get("Resource"))
        has_star_action = any(a == "*" for a in actions)
        has_star_resource = any(r == "*" for r in resources)
        if has_star_action and has_star_resource:
            return True
    return False


def extract_passrole_resources(policy_document: dict) -> list[str]:
    """Return the Resource patterns (role ARNs, or '*') that this policy
    allows iam:PassRole against. Used to build PassRole edges later."""
    resources: list[str] = []
    for s in statements(policy_document):
        if s.get("Effect") != "Allow":
            continue
        actions = _as_list(s.get("Action"))
        if any(action_matches(a, "iam:PassRole") for a in actions):
            resources.extend(_as_list(s.get("Resource")))
    return resources


def extract_trust_principals(trust_policy: dict) -> list[dict]:
    """Parse a role's AssumeRolePolicyDocument and return the list of
    principals allowed to assume it (and which sts action they're granted).

    Each returned dict looks like:
      {"principal_type": "AWS", "principal": "arn:aws:iam::123:role/Foo", "action": "sts:AssumeRole"}
      {"principal_type": "Service", "principal": "ec2.amazonaws.com", "action": "sts:AssumeRole"}
      {"principal_type": "Federated", "principal": "...", "action": "sts:AssumeRoleWithWebIdentity"}
    """
    results: list[dict] = []
    for s in statements(trust_policy):
        if s.get("Effect") != "Allow":
            continue
        principal_block = s.get("Principal", {})
        actions = _as_list(s.get("Action"))

        # Principal can be the literal string "*" (anyone) or a dict keyed
        # by principal type (AWS, Service, Federated, CanonicalUser).
        if isinstance(principal_block, str):
            principal_items = [("AWS", principal_block)]
        else:
            principal_items = []
            for ptype, pvals in principal_block.items():
                for pval in _as_list(pvals):
                    principal_items.append((ptype, pval))

        for ptype, pval in principal_items:
            for action in actions:
                results.append(
                    {
                        "principal_type": ptype,
                        "principal": pval,
                        "action": action,
                    }
                )
    return results


def is_admin_role(
    attached_policy_arns: Iterable[str],
    policy_documents: Iterable[dict],
) -> bool:
    """A role counts as 'admin' (a sink in the escalation graph) if either:
      1. AdministratorAccess is directly attached, or
      2. any policy document we were able to read effectively grants
         full admin (Action='*' on Resource='*').

    `policy_documents` should include the resolved JSON of every attached
    managed policy version AND every inline policy on the role.
    """
    if ADMIN_POLICY_ARN in attached_policy_arns:
        return True
    return any(policy_grants_full_admin(doc) for doc in policy_documents)
