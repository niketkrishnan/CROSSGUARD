"""Tests for ingestion/policy_utils.py -- pure logic, no AWS/K8s needed."""

from ingestion.policy_utils import (
    action_matches,
    extract_passrole_resources,
    extract_trust_principals,
    is_admin_role,
    policy_grants_action,
    policy_grants_full_admin,
)


def test_action_matches_exact():
    assert action_matches("iam:PassRole", "iam:PassRole")
    assert action_matches("iam:passrole", "IAM:PASSROLE")  # case-insensitive


def test_action_matches_wildcard():
    assert action_matches("iam:*", "iam:PassRole")
    assert action_matches("*", "anything:AtAll")
    assert action_matches("s3:Get*", "s3:GetObject")
    assert not action_matches("s3:Get*", "s3:PutObject")


def test_policy_grants_action_single_string_action():
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}],
    }
    assert policy_grants_action(policy, "iam:PassRole")
    assert not policy_grants_action(policy, "s3:GetObject")


def test_policy_grants_action_list_of_actions():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "iam:PassRole"],
                "Resource": "*",
            }
        ]
    }
    assert policy_grants_action(policy, "iam:PassRole")


def test_deny_statement_does_not_grant():
    policy = {"Statement": [{"Effect": "Deny", "Action": "iam:PassRole", "Resource": "*"}]}
    assert not policy_grants_action(policy, "iam:PassRole")


def test_policy_grants_full_admin_true():
    admin_policy = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    assert policy_grants_full_admin(admin_policy)


def test_policy_grants_full_admin_false_for_scoped_policy():
    scoped_policy = {
        "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]
    }
    assert not policy_grants_full_admin(scoped_policy)


def test_extract_passrole_resources():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "arn:aws:iam::123456789012:role/TargetRole",
            },
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
        ]
    }
    resources = extract_passrole_resources(policy)
    assert resources == ["arn:aws:iam::123456789012:role/TargetRole"]


def test_extract_passrole_resources_wildcard_action():
    # iam:* implies PassRole too -- this is a classic over-permissive policy
    policy = {"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}
    assert extract_passrole_resources(policy) == ["*"]


def test_extract_trust_principals_aws_principal():
    trust_policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:role/Caller"},
                "Action": "sts:AssumeRole",
            }
        ]
    }
    principals = extract_trust_principals(trust_policy)
    assert principals == [
        {
            "principal_type": "AWS",
            "principal": "arn:aws:iam::123456789012:role/Caller",
            "action": "sts:AssumeRole",
        }
    ]


def test_extract_trust_principals_service_principal():
    trust_policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ]
    }
    principals = extract_trust_principals(trust_policy)
    assert principals[0]["principal_type"] == "Service"
    assert principals[0]["principal"] == "ec2.amazonaws.com"


def test_extract_trust_principals_wildcard_string_principal():
    # A bare "*" principal means "anyone" -- common misconfiguration
    trust_policy = {
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]
    }
    principals = extract_trust_principals(trust_policy)
    assert principals == [{"principal_type": "AWS", "principal": "*", "action": "sts:AssumeRole"}]


def test_extract_trust_principals_multiple_principals_same_statement():
    trust_policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": [
                        "arn:aws:iam::123456789012:role/A",
                        "arn:aws:iam::123456789012:role/B",
                    ]
                },
                "Action": "sts:AssumeRole",
            }
        ]
    }
    principals = extract_trust_principals(trust_policy)
    assert len(principals) == 2
    arns = {p["principal"] for p in principals}
    assert arns == {
        "arn:aws:iam::123456789012:role/A",
        "arn:aws:iam::123456789012:role/B",
    }


def test_is_admin_role_via_managed_policy_arn():
    assert is_admin_role(
        attached_policy_arns=["arn:aws:iam::aws:policy/AdministratorAccess"],
        policy_documents=[],
    )


def test_is_admin_role_via_inline_star_star_policy():
    inline_admin_doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    assert is_admin_role(attached_policy_arns=[], policy_documents=[inline_admin_doc])


def test_is_admin_role_false_for_scoped_role():
    scoped_doc = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
    assert not is_admin_role(
        attached_policy_arns=["arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"],
        policy_documents=[scoped_doc],
    )
