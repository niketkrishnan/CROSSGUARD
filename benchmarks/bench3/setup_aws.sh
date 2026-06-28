#!/bin/bash
# Benchmark 3 -- 5 ServiceAccounts exist, only 1 has the IRSA annotation.
# Tests that the tool doesn't hallucinate paths from the other 4.
set -e

export AWS_DEFAULT_REGION=us-east-1
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test

awslocal iam create-role --role-name b3-admin-role \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

awslocal iam attach-role-policy \
  --role-name b3-admin-role \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

echo "Benchmark 3 AWS setup complete."
