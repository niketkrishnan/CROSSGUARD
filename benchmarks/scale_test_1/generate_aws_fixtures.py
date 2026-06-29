"""
benchmarks/scale_test_1/generate_aws_fixtures.py

Generates a realistically-sized AWS IAM fixture set against LocalStack:
- 50 users, each with one inline policy (low-priv)
- 98 plain roles, each with one inline policy (low-priv)
- 2 admin roles, with AdministratorAccess attached
Total: 150 inline policies + 2 managed policy attachments ~= 200 "policies"
as referenced in the scale test plan.

Run with: python3 benchmarks/scale_test_1/generate_aws_fixtures.py
"""

import json

import boto3

iam = boto3.client(
    "iam",
    endpoint_url="http://localhost:4566",
    region_name="us-east-1",
    aws_access_key_id="test",
    aws_secret_access_key="test",
)

TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}

LOW_PRIV_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
}

print("Creating 50 users...")
for i in range(50):
    user_name = f"scale-user-{i}"
    iam.create_user(UserName=user_name)
    iam.put_user_policy(
        UserName=user_name,
        PolicyName="low-priv",
        PolicyDocument=json.dumps(LOW_PRIV_POLICY),
    )
print("  done.")

print("Creating 98 plain roles...")
for i in range(98):
    role_name = f"scale-role-{i}"
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
    )
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="low-priv",
        PolicyDocument=json.dumps(LOW_PRIV_POLICY),
    )
print("  done.")

print("Creating 2 admin roles...")
for name in ("scale-admin-role-A", "scale-admin-role-B"):
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(TRUST_POLICY))
    iam.attach_role_policy(
        RoleName=name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
    )
print("  done.")

print("Scale Test 1 AWS fixtures created: 50 users, 100 roles (98 plain + 2 admin).")
