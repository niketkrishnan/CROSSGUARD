"""
evaluation/real_world/published_policies/build_cases.py

Builds CrossGuard test cases from the real published policies in
policies.py, plus one case modeling the specific privilege-escalation
pattern documented in Unit 42's "Misconfigured IAM Roles Lead to Thousands
of Compromised Cloud Workloads" report (unit42.paloaltonetworks.com/
iam-roles-compromised-workloads/, cited in the paper's related-work review
as one of the Unit 42 industry reports): "a risky combination of policies
that allow users with an IAM role to elevate to AdministratorAccess."

That description is generic (Unit 42 does not publish the exact policy
JSON from the account they investigated), so the case below is not a
verbatim artifact the way the four negatives are -- it is CrossGuard's own
PassRole-plus-paired-action mechanism (already validated in
policy_semantics and generated_benchmark), applied to a scenario matching
the report's description, with the source cited rather than presented as
extracted. This is disclosed explicitly, here and in the results doc: it
is the one case in this set that is NOT a verbatim published artifact.

Every case uses a real OIDC trust statement (matching every other IRSA
fixture built in this evaluation) and the account ID that matches
LocalStack's real default test account (see generator.py / replay.py).
"""

from __future__ import annotations

import copy

from evaluation.real_world.published_policies.policies import ACCOUNT, REAL_POLICIES

OIDC_HOST = "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"
OIDC_PROVIDER_ARN = f"arn:aws:iam::{ACCOUNT}:oidc-provider/{OIDC_HOST}"


def arn_role(name):
    return f"arn:aws:iam::{ACCOUNT}:role/{name}"


def oidc_trust(sa, ns):
    return {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Federated": OIDC_PROVIDER_ARN},
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Condition": {"StringEquals": {f"{OIDC_HOST}:sub": f"system:serviceaccount:{ns}:{sa}",
                                       f"{OIDC_HOST}:aud": "sts.amazonaws.com"}},
    }]}


def negative_cases():
    """The four real published policies, each IRSA-bound with a valid OIDC
    trust and nothing else. Truth: 0 cross-layer paths in every case --
    none of these policies grant PassRole, AssumeRole, or admin."""
    out = {}
    for name, entry in REAL_POLICIES.items():
        role_name = f"{name}-role"
        out[f"RWP-{name}"] = {
            "case_id": f"RWP-{name}", "source": entry["source"], "fully_verbatim": entry["fully_verbatim"],
            "roles": [{
                "Arn": arn_role(role_name), "RoleName": role_name, "is_admin": False,
                "AssumeRolePolicyDocument": oidc_trust(entry["sa_name"], entry["namespace"]),
                "policy_documents": [entry["policy"]],
                "trust_principals": [], "passrole_resources": [],
            }],
            "sa_role_map": {entry["sa_name"]: role_name},
            "entry_sa": entry["sa_name"], "entry_ns": entry["namespace"],
            "truth": {"reachable": False, "confidence": None, "target": None,
                     "mechanism": f"real, as-published least-privilege policy for {name}; no admin/PassRole/AssumeRole grant"},
        }
    return out


def positive_case_unit42_pattern():
    """Models Unit 42's documented pattern: a role whose own policy is not
    itself admin, but which can PassRole onto (and, via a paired action,
    actually use) a role that IS admin -- 'a risky combination of policies
    that allow users with an IAM role to elevate to AdministratorAccess.'
    See this module's docstring: sourced from a documented pattern, not a
    verbatim extracted policy."""
    entry_sa, ns = "deploy-controller", "default"
    entry_role, admin_role = "deploy-controller-role", "ci-deploy-admin-role"
    entry = {
        "Arn": arn_role(entry_role), "RoleName": entry_role, "is_admin": False,
        "AssumeRolePolicyDocument": oidc_trust(entry_sa, ns),
        "policy_documents": [{
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "iam:PassRole", "Resource": arn_role(admin_role)},
                {"Effect": "Allow", "Action": "cloudformation:CreateStack", "Resource": "*"},
            ],
        }],
        "trust_principals": [], "passrole_resources": [],
    }
    admin = {
        "Arn": arn_role(admin_role), "RoleName": admin_role, "is_admin": True,
        "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "cloudformation.amazonaws.com"}, "Action": "sts:AssumeRole"},
        ]},
        "policy_documents": [{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}],
        "trust_principals": [], "passrole_resources": [],
    }
    return {"RWP-unit42-passrole-chain": {
        "case_id": "RWP-unit42-passrole-chain",
        "source": "https://unit42.paloaltonetworks.com/iam-roles-compromised-workloads/ "
                  "(pattern description, not a verbatim policy -- see module docstring)",
        "fully_verbatim": False,
        "roles": [entry, admin], "sa_role_map": {entry_sa: entry_role}, "entry_sa": entry_sa, "entry_ns": ns,
        "truth": {"reachable": True, "confidence": "confirmed", "target": arn_role(admin_role),
                 "mechanism": "PassRole + paired cloudformation:CreateStack action reaches an admin-labeled role -- "
                             "models the Unit 42-documented 'risky combination of policies' pattern"},
    }}


def all_cases():
    cases = {}
    cases.update(negative_cases())
    cases.update(positive_case_unit42_pattern())
    return cases
