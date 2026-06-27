"""
ingestion/aws_ingestion.py

Pulls AWS IAM configuration via boto3 and enriches it with everything the
graph builder (Module 2) needs: resolved policy documents, trust-policy
principals, iam:PassRole grants, and an is_admin flag per role.

Works against real AWS or against LocalStack -- just pass `endpoint_url`
(e.g. "http://localhost:4566") to point at LocalStack.
"""

from __future__ import annotations

import logging
from typing import Any

import boto3

from ingestion.policy_utils import (
    extract_passrole_resources,
    extract_trust_principals,
    is_admin_role,
)

logger = logging.getLogger(__name__)


def _make_iam_client(profile: str | None, endpoint_url: str | None, region: str):
    session = boto3.Session(profile_name=profile)
    kwargs: dict[str, Any] = {"region_name": region}
    if endpoint_url:
        kwargs["endpoint_url"] = endpoint_url
        # LocalStack doesn't care about real creds, but boto3 still wants
        # *something* set if the environment has none configured.
        kwargs.setdefault("aws_access_key_id", "test")
        kwargs.setdefault("aws_secret_access_key", "test")
    return session.client("iam", **kwargs)


def _paginate(iam_client, operation_name: str, result_key: str, **kwargs) -> list[dict]:
    """Use boto3's built-in paginator so we don't silently truncate at the
    default 100-item page (real AWS accounts can have far more)."""
    items: list[dict] = []
    paginator = iam_client.get_paginator(operation_name)
    for page in paginator.paginate(**kwargs):
        items.extend(page[result_key])
    return items


def _resolve_attached_policy_documents(iam_client, attached_policies: list[dict]) -> list[dict]:
    """attached_policies come from list_attached_*_policies and only give
    {PolicyName, PolicyArn} -- fetch the actual (default version) JSON."""
    documents = []
    for policy in attached_policies:
        arn = policy["PolicyArn"]
        try:
            policy_meta = iam_client.get_policy(PolicyArn=arn)["Policy"]
            version_id = policy_meta["DefaultVersionId"]
            version = iam_client.get_policy_version(PolicyArn=arn, VersionId=version_id)
            documents.append(version["PolicyVersion"]["Document"])
        except Exception:  # noqa: BLE001 - ingestion should be best-effort, not fatal
            logger.warning("Could not resolve attached policy %s", arn, exc_info=True)
    return documents


def _resolve_inline_policy_documents(
    iam_client, entity_type: str, entity_name: str, inline_policy_names: list[str]
) -> list[dict]:
    """entity_type is one of 'role', 'user', 'group' -- each has its own
    get_*_policy API call but identical response shape."""
    get_method = getattr(iam_client, f"get_{entity_type}_policy")
    name_kwarg = f"{entity_type.capitalize()}Name"
    documents = []
    for policy_name in inline_policy_names:
        try:
            response = get_method(**{name_kwarg: entity_name, "PolicyName": policy_name})
            documents.append(response["PolicyDocument"])
        except Exception:  # noqa: BLE001
            logger.warning(
                "Could not resolve inline policy %s on %s %s",
                policy_name,
                entity_type,
                entity_name,
                exc_info=True,
            )
    return documents


def _enrich_role(iam_client, role: dict) -> dict:
    role_name = role["RoleName"]

    attached = _paginate(
        iam_client,
        "list_attached_role_policies",
        "AttachedPolicies",
        RoleName=role_name,
    )
    inline_names = _paginate(
        iam_client, "list_role_policies", "PolicyNames", RoleName=role_name
    )

    attached_documents = _resolve_attached_policy_documents(iam_client, attached)
    inline_documents = _resolve_inline_policy_documents(iam_client, "role", role_name, inline_names)
    all_documents = attached_documents + inline_documents

    trust_policy = role.get("AssumeRolePolicyDocument", {})

    passrole_resources: list[str] = []
    for doc in all_documents:
        passrole_resources.extend(extract_passrole_resources(doc))

    return {
        **role,
        "attached_policies": attached,
        "inline_policy_names": inline_names,
        "policy_documents": all_documents,
        "trust_principals": extract_trust_principals(trust_policy),
        "passrole_resources": passrole_resources,
        "is_admin": is_admin_role(
            (p["PolicyArn"] for p in attached), all_documents
        ),
    }


def _enrich_group(iam_client, group: dict) -> dict:
    group_name = group["GroupName"]

    attached = _paginate(
        iam_client,
        "list_attached_group_policies",
        "AttachedPolicies",
        GroupName=group_name,
    )
    inline_names = _paginate(
        iam_client, "list_group_policies", "PolicyNames", GroupName=group_name
    )
    members = _paginate(
        iam_client, "get_group", "Users", GroupName=group_name
    )

    attached_documents = _resolve_attached_policy_documents(iam_client, attached)
    inline_documents = _resolve_inline_policy_documents(
        iam_client, "group", group_name, inline_names
    )
    all_documents = attached_documents + inline_documents

    return {
        **group,
        "attached_policies": attached,
        "inline_policy_names": inline_names,
        "policy_documents": all_documents,
        "member_arns": [u["Arn"] for u in members],
        "is_admin": is_admin_role((p["PolicyArn"] for p in attached), all_documents),
    }


def _enrich_user(iam_client, user: dict) -> dict:
    user_name = user["UserName"]

    attached = _paginate(
        iam_client,
        "list_attached_user_policies",
        "AttachedPolicies",
        UserName=user_name,
    )
    inline_names = _paginate(
        iam_client, "list_user_policies", "PolicyNames", UserName=user_name
    )
    group_memberships = _paginate(
        iam_client, "list_groups_for_user", "Groups", UserName=user_name
    )

    attached_documents = _resolve_attached_policy_documents(iam_client, attached)
    inline_documents = _resolve_inline_policy_documents(iam_client, "user", user_name, inline_names)
    all_documents = attached_documents + inline_documents

    passrole_resources: list[str] = []
    for doc in all_documents:
        passrole_resources.extend(extract_passrole_resources(doc))

    return {
        **user,
        "attached_policies": attached,
        "inline_policy_names": inline_names,
        "policy_documents": all_documents,
        "group_arns": [g["Arn"] for g in group_memberships],
        "passrole_resources": passrole_resources,
        "is_admin": is_admin_role((p["PolicyArn"] for p in attached), all_documents),
    }


def ingest_aws(
    profile: str | None = None,
    endpoint_url: str | None = None,
    region: str = "us-east-1",
) -> dict:
    """Pull and enrich all AWS IAM entities needed for the unified graph.

    Args:
        profile: named AWS CLI profile to use (None = default credential chain).
        endpoint_url: set to "http://localhost:4566" to target LocalStack
            instead of real AWS.
        region: AWS region (LocalStack ignores this but boto3 requires it).

    Returns:
        {"users": [...], "roles": [...], "groups": [...]}
        Each entity dict is the raw boto3 object PLUS the enrichment fields
        added above (policy_documents, trust_principals, is_admin, etc).
    """
    iam = _make_iam_client(profile, endpoint_url, region)

    logger.info("Listing IAM users/roles/groups...")
    raw_users = _paginate(iam, "list_users", "Users")
    raw_roles = _paginate(iam, "list_roles", "Roles")
    raw_groups = _paginate(iam, "list_groups", "Groups")

    logger.info("Enriching %d roles with policies/trust/passrole...", len(raw_roles))
    roles = [_enrich_role(iam, r) for r in raw_roles]

    logger.info("Enriching %d groups...", len(raw_groups))
    groups = [_enrich_group(iam, g) for g in raw_groups]

    logger.info("Enriching %d users...", len(raw_users))
    users = [_enrich_user(iam, u) for u in raw_users]

    return {"users": users, "roles": roles, "groups": groups}
