#!/bin/bash
# Benchmark 2 -- multi-hop IAM chain after IRSA.
# vulnerable-sa --(IRSA)--> role-a --(iam:PassRole)--> role-b --(sts:AssumeRole)--> admin-role
set -e

export AWS_DEFAULT_REGION=us-east-1
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test

# admin-role: the actual target -- has AdministratorAccess
awslocal iam create-role --role-name b2-admin-role \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:role/b2-role-b"},"Action":"sts:AssumeRole"}]}'

awslocal iam attach-role-policy \
  --role-name b2-admin-role \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# role-b: can assume b2-admin-role (trust policy above already allows it).
# Also needs to exist as a role itself.
awslocal iam create-role --role-name b2-role-b \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:role/b2-role-a"},"Action":"sts:AssumeRole"}]}'

# role-a: this is what the IRSA annotation will point to.
# It has iam:PassRole permission scoped to role-b.
awslocal iam create-role --role-name b2-role-a \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

awslocal iam put-role-policy \
  --role-name b2-role-a \
  --policy-name allow-passrole-to-role-b \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::000000000000:role/b2-role-b"}]}'

echo "Benchmark 2 AWS setup complete."
