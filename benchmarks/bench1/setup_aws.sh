#!/bin/bash
# Benchmark 1 -- AWS side setup.
# Run this against LocalStack: docker run -d --name localstack -p 4566:4566 localstack/localstack:4.14.0
set -e

export AWS_DEFAULT_REGION=us-east-1
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test

awslocal iam create-role --role-name admin-role \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::000000000000:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:sub":"system:serviceaccount:default:vulnerable-sa","oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:aud":"sts.amazonaws.com"}}}]}'

awslocal iam attach-role-policy \
  --role-name admin-role \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

awslocal iam create-user --user-name low-priv-user

echo "Benchmark 1 AWS setup complete."
