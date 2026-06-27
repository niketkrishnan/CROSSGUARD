"""Tests for ingestion/aws_ingestion.py's ingest_aws() end-to-end, against
a fully mocked IAM client (no real boto3/LocalStack needed).

We monkeypatch aws_ingestion._make_iam_client to return a fake client
object whose methods return canned boto3-shaped responses. This proves
the pagination/enrichment/is_admin wiring works correctly before you
ever point it at real LocalStack.
"""

import ingestion.aws_ingestion as aws_ingestion


class FakeIamClient:
    """Mimics just enough of the boto3 IAM client surface for ingest_aws()
    to run against a single scripted scenario: one low-priv user, one
    PassRole-capable role, and one AdministratorAccess role."""

    def __init__(self):
        self._roles = [
            {
                "RoleName": "admin-role",
                "Arn": "arn:aws:iam::000000000000:role/admin-role",
                "AssumeRolePolicyDocument": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::000000000000:role/passrole-role"},
                            "Action": "sts:AssumeRole",
                        }
                    ]
                },
            },
            {
                "RoleName": "passrole-role",
                "Arn": "arn:aws:iam::000000000000:role/passrole-role",
                "AssumeRolePolicyDocument": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "eks.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ]
                },
            },
        ]
        self._users = [{"UserName": "low-priv-user", "Arn": "arn:aws:iam::000000000000:user/low-priv-user"}]
        self._groups = []

        self._attached_role_policies = {
            "admin-role": [
                {"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}
            ],
            "passrole-role": [],
        }
        self._inline_role_policy_names = {
            "admin-role": [],
            "passrole-role": ["allow-passrole"],
        }
        self._inline_role_policy_docs = {
            ("passrole-role", "allow-passrole"): {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "iam:PassRole",
                        "Resource": "arn:aws:iam::000000000000:role/admin-role",
                    }
                ]
            },
        }

    def get_paginator(self, operation_name):
        client = self

        class _Paginator:
            def paginate(self_inner, **kwargs):
                if operation_name == "list_users":
                    yield {"Users": client._users}
                elif operation_name == "list_roles":
                    yield {"Roles": client._roles}
                elif operation_name == "list_groups":
                    yield {"Groups": client._groups}
                elif operation_name == "list_attached_role_policies":
                    role_name = kwargs["RoleName"]
                    yield {"AttachedPolicies": client._attached_role_policies.get(role_name, [])}
                elif operation_name == "list_role_policies":
                    role_name = kwargs["RoleName"]
                    yield {"PolicyNames": client._inline_role_policy_names.get(role_name, [])}
                elif operation_name == "list_attached_group_policies":
                    yield {"AttachedPolicies": []}
                elif operation_name == "list_group_policies":
                    yield {"PolicyNames": []}
                elif operation_name == "get_group":
                    yield {"Users": []}
                elif operation_name == "list_attached_user_policies":
                    yield {"AttachedPolicies": []}
                elif operation_name == "list_user_policies":
                    yield {"PolicyNames": []}
                elif operation_name == "list_groups_for_user":
                    yield {"Groups": []}
                else:
                    raise NotImplementedError(operation_name)

        return _Paginator()

    def get_role_policy(self, RoleName, PolicyName):
        return {"PolicyDocument": self._inline_role_policy_docs[(RoleName, PolicyName)]}

    def get_user_policy(self, UserName, PolicyName):
        raise NotImplementedError  # no users have inline policies in this scenario

    def get_group_policy(self, GroupName, PolicyName):
        raise NotImplementedError  # no groups in this scenario

    def get_policy(self, PolicyArn):
        # Not exercised meaningfully here -- is_admin_role short-circuits on
        # the attached ARN match for AdministratorAccess instead. Left
        # raising so we'd notice if the code path changes later.
        raise NotImplementedError


def test_ingest_aws_end_to_end_with_mocked_client(monkeypatch):
    fake_client = FakeIamClient()
    monkeypatch.setattr(aws_ingestion, "_make_iam_client", lambda *a, **k: fake_client)

    result = aws_ingestion.ingest_aws(endpoint_url="http://localhost:4566")

    assert len(result["users"]) == 1
    assert len(result["roles"]) == 2
    assert result["groups"] == []

    roles_by_name = {r["RoleName"]: r for r in result["roles"]}

    admin_role = roles_by_name["admin-role"]
    assert admin_role["is_admin"] is True

    passrole_role = roles_by_name["passrole-role"]
    assert passrole_role["is_admin"] is False
    assert passrole_role["passrole_resources"] == ["arn:aws:iam::000000000000:role/admin-role"]

    assert passrole_role["trust_principals"] == [
        {"principal_type": "Service", "principal": "eks.amazonaws.com", "action": "sts:AssumeRole"}
    ]
