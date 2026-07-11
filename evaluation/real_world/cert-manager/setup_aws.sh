#!/bin/bash
# Real-world test: cert-manager IAM configuration
# cert-manager uses IRSA when integrated with Route53 for DNS01 challenges
# A common misconfiguration is giving it full Route53 access or AdministratorAccess
set -e

export AWS_DEFAULT_REGION=us-east-1
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test

# Misconfigured: full admin (seen when operators use admin roles for convenience)
awslocal iam create-role --role-name cert-manager \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

awslocal iam attach-role-policy \
  --role-name cert-manager \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Correctly scoped: Route53 change permissions for DNS01 only
awslocal iam create-role --role-name cert-manager-scoped \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

awslocal iam put-role-policy \
  --role-name cert-manager-scoped \
  --policy-name route53-dns01 \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["route53:GetChange"],"Resource":"arn:aws:route53:::change/*"},{"Effect":"Allow","Action":["route53:ChangeResourceRecordSets","route53:ListResourceRecordSets"],"Resource":"arn:aws:route53:::hostedzone/*"}]}'

echo "cert-manager AWS setup complete."
echo "  cert-manager: AdministratorAccess (MISCONFIGURED)"
echo "  cert-manager-scoped: Route53 DNS01 only (CORRECT)"
