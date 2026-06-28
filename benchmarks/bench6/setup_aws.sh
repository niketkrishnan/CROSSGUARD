#!/bin/bash
# Benchmark 6 -- one IRSA-bridged role with two escalation routes of
# different lengths, both leading to admin. Tests that risk scoring
# correctly ranks the shorter/more-direct path higher.
set -e

export AWS_DEFAULT_REGION=us-east-1
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test

# b6-role-a: the IRSA target. Not admin itself.
awslocal iam create-role --role-name b6-role-a \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

# Route 1 (SHORT, 2 hops from SA): role-a --PassRole--> admin-near
awslocal iam create-role --role-name b6-admin-near \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
awslocal iam attach-role-policy --role-name b6-admin-near --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

awslocal iam put-role-policy --role-name b6-role-a --policy-name allow-passrole-near \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::000000000000:role/b6-admin-near"}]}'

# Route 2 (LONG, 3 hops from SA): role-a --PassRole--> role-b --AssumeRole--> admin-far
awslocal iam create-role --role-name b6-admin-far \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:role/b6-role-b"},"Action":"sts:AssumeRole"}]}'
awslocal iam attach-role-policy --role-name b6-admin-far --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

awslocal iam create-role --role-name b6-role-b \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:role/b6-role-a"},"Action":"sts:AssumeRole"}]}'

awslocal iam put-role-policy --role-name b6-role-a --policy-name allow-passrole-far \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::000000000000:role/b6-role-b"}]}'

echo "Benchmark 6 AWS setup complete."
