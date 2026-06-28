#!/bin/bash
# Benchmark 4 -- group_membership edge completeness test.
# This is intentionally SAME-LAYER (AWS-only), not cross-layer: AWS IAM
# groups can only contain Users, and IRSA always lands in a Role's
# session, never a User's -- so a real IRSA->...->Group chain is not
# constructible on real AWS. See benchmarks/bench4/README.md.
#
# low-priv-user --(member of)--> admin-group (AdministratorAccess attached)
set -e

export AWS_DEFAULT_REGION=us-east-1
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test

awslocal iam create-group --group-name b4-admin-group

awslocal iam attach-group-policy \
  --group-name b4-admin-group \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

awslocal iam create-user --user-name b4-low-priv-user

awslocal iam add-user-to-group \
  --user-name b4-low-priv-user \
  --group-name b4-admin-group

echo "Benchmark 4 AWS setup complete."
