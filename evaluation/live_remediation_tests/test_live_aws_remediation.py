"""
Standalone live test for the two remediation paths no benchmark's
minimum-cut result happens to select: iam:PassRole and group_membership.

Unlike the benchmark suite, this doesn't go through the pathfinder or
scan pipeline at all -- it sets up real IAM entities on LocalStack,
calls core_adapter.apply_aws_edge_removal() directly with a crafted
edge_cut (exactly what the remediation engine would have produced), and
then re-queries LocalStack's IAM API to confirm the change actually
took effect. This proves the AWS API calls themselves are correct
against a real IAM implementation, independent of whether any
benchmark's graph happens to route through them.

Run with LocalStack up and the venv activated:
    export PYTHONPATH=~/projects/iam-k8s-privesc:$PYTHONPATH
    export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1
    python3 test_live_aws_remediation.py
"""
import json
import sys

import boto3

sys.path.insert(0, "crossguard-live-api/app")
import core_adapter as ca  # noqa: E402

IAM = boto3.client("iam", endpoint_url="http://localhost:4566", region_name="us-east-1")
ACCOUNT = "000000000000"


def cleanup():
    for name in ["live-test-passrole-user", "live-test-group-user"]:
        try:
            for pol in IAM.list_user_policies(UserName=name)["PolicyNames"]:
                IAM.delete_user_policy(UserName=name, PolicyName=pol)
            for grp in IAM.list_groups_for_user(UserName=name)["Groups"]:
                IAM.remove_user_from_group(UserName=name, GroupName=grp["GroupName"])
            IAM.delete_user(UserName=name)
        except IAM.exceptions.NoSuchEntityException:
            pass
    for name in ["live-test-target-role", "live-test-admin-group"]:
        try:
            if "role" in name:
                IAM.delete_role(RoleName=name)
            else:
                IAM.delete_group(GroupName=name)
        except IAM.exceptions.NoSuchEntityException:
            pass


def test_passrole():
    print("--- iam:PassRole live test ---")
    IAM.create_role(
        RoleName="live-test-target-role",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }),
    )
    IAM.create_user(UserName="live-test-passrole-user")
    target_arn = f"arn:aws:iam::{ACCOUNT}:role/live-test-target-role"
    IAM.put_user_policy(
        UserName="live-test-passrole-user",
        PolicyName="grants-passrole-and-s3",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "iam:PassRole", "Resource": target_arn},
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
            ],
        }),
    )

    before = IAM.get_user_policy(UserName="live-test-passrole-user", PolicyName="grants-passrole-and-s3")["PolicyDocument"]
    assert len(before["Statement"]) == 2
    print("BEFORE: 2 statements (PassRole + s3:GetObject) confirmed on live LocalStack")

    ca.apply_aws_edge_removal(IAM, {
        "edge_type": "iam:PassRole",
        "source": f"arn:aws:iam::{ACCOUNT}:user/live-test-passrole-user",
        "target": target_arn,
    })

    after = IAM.get_user_policy(UserName="live-test-passrole-user", PolicyName="grants-passrole-and-s3")["PolicyDocument"]
    actions_left = [s["Action"] for s in after["Statement"]]
    assert actions_left == ["s3:GetObject"], f"Expected only s3:GetObject left, got {actions_left}"
    print("AFTER:  PassRole statement removed, s3:GetObject statement untouched")
    print("PASSED\n")


def test_group_membership():
    print("--- group_membership live test ---")
    IAM.create_group(GroupName="live-test-admin-group")
    IAM.attach_group_policy(GroupName="live-test-admin-group", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    IAM.create_user(UserName="live-test-group-user")
    IAM.add_user_to_group(GroupName="live-test-admin-group", UserName="live-test-group-user")

    before = IAM.list_groups_for_user(UserName="live-test-group-user")["Groups"]
    assert any(g["GroupName"] == "live-test-admin-group" for g in before)
    print("BEFORE: user confirmed a member of live-test-admin-group on live LocalStack")

    ca.apply_aws_edge_removal(IAM, {
        "edge_type": "group_membership",
        "source": f"arn:aws:iam::{ACCOUNT}:user/live-test-group-user",
        "target": f"arn:aws:iam::{ACCOUNT}:group/live-test-admin-group",
    })

    after = IAM.list_groups_for_user(UserName="live-test-group-user")["Groups"]
    assert not any(g["GroupName"] == "live-test-admin-group" for g in after)
    print("AFTER:  user no longer a member of live-test-admin-group")
    print("PASSED\n")


if __name__ == "__main__":
    cleanup()
    try:
        test_passrole()
        test_group_membership()
        print("ALL LIVE TESTS PASSED")
    finally:
        cleanup()
