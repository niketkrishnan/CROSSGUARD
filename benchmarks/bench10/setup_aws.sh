#!/bin/bash
# Benchmark 10 -- FP stress test: 15 diverse SAFE configurations, each
# deliberately designed to LOOK potentially risky on the surface but
# have no real path to admin. Ground truth: ALL should produce 0
# cross-layer paths. Includes 2 genuinely tricky edge cases (MFA-gated
# trust, explicit Deny) to honestly probe for real limitations.
set -e
export AWS_DEFAULT_REGION=us-east-1
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test

mkrole() { # name, trust_json
  awslocal iam create-role --role-name "$1" --assume-role-policy-document "$2" >/dev/null
}
putpol() { # role, policy_name, policy_json
  awslocal iam put-role-policy --role-name "$1" --policy-name "$2" --policy-document "$3" >/dev/null
}

TRUST_EC2='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

# 1. S3 read-only
mkrole b10-s3-readonly "$TRUST_EC2"
awslocal iam attach-role-policy --role-name b10-s3-readonly --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess

# 2. DynamoDB read-only
mkrole b10-ddb-readonly "$TRUST_EC2"
awslocal iam attach-role-policy --role-name b10-ddb-readonly --policy-arn arn:aws:iam::aws:policy/AmazonDynamoDBReadOnlyAccess

# 3. CloudWatch read-only
mkrole b10-cw-readonly "$TRUST_EC2"
awslocal iam attach-role-policy --role-name b10-cw-readonly --policy-arn arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess

# 4. Scoped PassRole (to a non-admin role) -- reachable target role
mkrole b10-passrole-target "$TRUST_EC2"
awslocal iam attach-role-policy --role-name b10-passrole-target --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
mkrole b10-passrole-scoped "$TRUST_EC2"
putpol b10-passrole-scoped scoped-passrole '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::000000000000:role/b10-passrole-target"}]}'

# 5. Wildcarded but safe service action (logs:*)
mkrole b10-logs-wildcard "$TRUST_EC2"
putpol b10-logs-wildcard logs-wildcard '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"logs:*","Resource":"*"}]}'

# 6. Resource-scoped s3:* (broad action, narrow resource)
mkrole b10-s3-scoped-star "$TRUST_EC2"
putpol b10-s3-scoped-star s3-scoped '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":["arn:aws:s3:::b10-app-bucket","arn:aws:s3:::b10-app-bucket/*"]}]}'

# 7. IAM read-only (ListRoles/GetRole, no write/pass)
mkrole b10-iam-readonly "$TRUST_EC2"
putpol b10-iam-readonly iam-readonly '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:GetRole","iam:ListRoles"],"Resource":"*"}]}'

# 8. Minimal -- only sts:GetCallerIdentity
mkrole b10-minimal "$TRUST_EC2"
putpol b10-minimal minimal-perms '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:GetCallerIdentity","Resource":"*"}]}'

# 9. EC2 describe-only (read-only wildcard on a compute service)
mkrole b10-ec2-describe "$TRUST_EC2"
putpol b10-ec2-describe ec2-describe '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:Describe*","Resource":"*"}]}'

# 10. Safe AssumeRole chain (assumes another non-admin role, chain ends safely)
mkrole b10-chain-end "$TRUST_EC2"
awslocal iam attach-role-policy --role-name b10-chain-end --policy-arn arn:aws:iam::aws:policy/AmazonDynamoDBReadOnlyAccess
mkrole b10-chain-start '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
putpol b10-chain-start assume-safe-chain '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"arn:aws:iam::000000000000:role/b10-chain-end"}]}'
# update b10-chain-end's trust to allow b10-chain-start
awslocal iam update-assume-role-policy --role-name b10-chain-end --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:role/b10-chain-start"},"Action":"sts:AssumeRole"},{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

# 11. Group membership, scoped (non-admin) group
awslocal iam create-group --group-name b10-scoped-group >/dev/null
awslocal iam attach-group-policy --group-name b10-scoped-group --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess

# 12. Scoped PassRole via iam:PassedToService condition (narrows to one service)
mkrole b10-passrole-conditioned "$TRUST_EC2"
putpol b10-passrole-conditioned conditioned-passrole '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*","Condition":{"StringEquals":{"iam:PassedToService":"ec2.amazonaws.com"}}}]}'

# 13. Dangling permission -- role has sts:AssumeRole to a real role, but the SA
# using this role will have NO IRSA annotation applied (unreachable from K8s at all)
mkrole b10-dangling "$TRUST_EC2"
putpol b10-dangling dangling-assume '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"arn:aws:iam::000000000000:role/b10-s3-readonly"}]}'

# 14 (TRICKY -- edge case). Admin role, but trust policy requires MFA
# (IRSA/OIDC federation cannot satisfy an MFA condition -- role should be
# UNREACHABLE via IRSA even though it has AdministratorAccess. Tests
# whether CrossGuard evaluates trust-policy conditions or only presence
# of a trust relationship.)
mkrole b10-mfa-gated-admin '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]}'
awslocal iam attach-role-policy --role-name b10-mfa-gated-admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 15 (TRICKY -- edge case). Explicit Deny on all actions, despite having
# AdministratorAccess attached (Deny always wins in AWS evaluation --
# role is genuinely inert regardless of the attached policy)
mkrole b10-explicit-deny-admin "$TRUST_EC2"
awslocal iam attach-role-policy --role-name b10-explicit-deny-admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
putpol b10-explicit-deny-admin explicit-deny-all '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'

echo "Benchmark 10 AWS setup complete: 15 diverse safe configs (13 standard + 2 tricky edge cases)."
