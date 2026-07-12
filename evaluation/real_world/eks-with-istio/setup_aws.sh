#!/bin/bash
# Real-world test: eks-with-istio (github.com/msfidelis/eks-with-istio)
# This repo uses IRSA for its sample application SA and has iam:PassRole
# in iam_karpenter.tf -- we model the realistic risk where the app SA
# gets an over-privileged role (seen in dev/staging environments)
set -e

export AWS_DEFAULT_REGION=us-east-1
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test

# The Karpenter node provisioner role -- in the real repo this has
# iam:PassRole which could be abused if also given to an app SA
awslocal iam create-role --role-name eks-istio-karpenter \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

awslocal iam attach-role-policy \
  --role-name eks-istio-karpenter \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# The correctly scoped app role
awslocal iam create-role --role-name eks-istio-app-scoped \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

awslocal iam put-role-policy \
  --role-name eks-istio-app-scoped \
  --policy-name app-permissions \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"arn:aws:s3:::my-app-bucket/*"}]}'

echo "eks-with-istio AWS setup complete."
echo "  eks-istio-karpenter: AdministratorAccess (MISCONFIGURED)"
echo "  eks-istio-app-scoped: S3 app bucket only (CORRECT)"
