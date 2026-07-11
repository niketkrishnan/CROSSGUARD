#!/bin/bash
# Real-world test: External Secrets Operator IAM configuration
# Models two real deployment patterns seen in production EKS clusters
set -e

export AWS_DEFAULT_REGION=us-east-1
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test

# Pattern 1 (MISCONFIGURED): operator given full SecretsManager access
# seen in real orgs that use wildcard policies for convenience
awslocal iam create-role --role-name external-secrets-operator \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

awslocal iam attach-role-policy \
  --role-name external-secrets-operator \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Pattern 2 (CORRECT): scoped to specific secret paths only
awslocal iam create-role --role-name external-secrets-operator-scoped \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

awslocal iam put-role-policy \
  --role-name external-secrets-operator-scoped \
  --policy-name scoped-secrets-access \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["secretsmanager:GetSecretValue","secretsmanager:DescribeSecret"],"Resource":"arn:aws:secretsmanager:us-east-1:000000000000:secret:myapp/*"}]}'

echo "External Secrets AWS setup complete."
echo "  external-secrets-operator: AdministratorAccess (MISCONFIGURED)"
echo "  external-secrets-operator-scoped: scoped to myapp/* secrets only (CORRECT)"
