"""
benchmarks/scale_test_2/generate_deep_chain.py

Generates a 10-hop AWS IAM role chain:
SA --IRSA--> role-1 --PassRole--> role-2 --PassRole--> ... --PassRole--> role-10 (AdministratorAccess)

Run with: python3 benchmarks/scale_test_2/generate_deep_chain.py
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

NUM_ROLES = 10

print(f"Creating {NUM_ROLES} roles in a chain...")
for i in range(1, NUM_ROLES + 1):
    role_name = f"deep-role-{i}"
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(TRUST_POLICY))

# Each role 1..9 gets PassRole permission to the NEXT role in the chain.
for i in range(1, NUM_ROLES):
    source_role = f"deep-role-{i}"
    target_role = f"deep-role-{i + 1}"
    target_arn = f"arn:aws:iam::000000000000:role/{target_role}"
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": target_arn}],
    }
    iam.put_role_policy(
        RoleName=source_role,
        PolicyName=f"passrole-to-{target_role}",
        PolicyDocument=json.dumps(policy),
    )

# The final role in the chain is the admin target.
iam.attach_role_policy(
    RoleName=f"deep-role-{NUM_ROLES}",
    PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
)

print(f"Deep chain created: deep-role-1 -> deep-role-2 -> ... -> deep-role-{NUM_ROLES} (admin).")
