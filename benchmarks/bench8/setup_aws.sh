#!/bin/bash
# Benchmark 8 -- PassRole-as-unique-cut-edge isolation test.
# Two SAs converge on the same intermediate role, which has a scoped
# iam:PassRole grant directly to an admin role. Forces the global
# min-cut to select the shared PassRole edge over the two separate
# IRSA edges (1 cut vs 2), isolating PassRole as the actual remediation.
set -e

export AWS_DEFAULT_REGION=us-east-1
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test

awslocal iam create-role --role-name b8-admin \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

awslocal iam attach-role-policy \
  --role-name b8-admin \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

awslocal iam create-role --role-name b8-role-shared \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

awslocal iam put-role-policy \
  --role-name b8-role-shared \
  --policy-name allow-passrole-to-admin \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::000000000000:role/b8-admin"}]}'

echo "Benchmark 8 AWS setup complete."
