#!/bin/bash
# Benchmark 9 -- realistic near-miss tests using REAL SA names extracted
# from real-world repos (this session), bound to genuinely PARTIAL-privilege
# roles requiring multi-hop graph reasoning -- not a binary admin/not-admin
# toggle. 2 should be flagged (subtle multi-hop escalation), 2 should not
# (scoped permissions that look risky but don't actually reach admin).
set -e
export AWS_DEFAULT_REGION=us-east-1
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test

# --- Case A (TP expected): cluster-autoscaler -- scoped autoscaling perms,
# PLUS an incidental iam:PassRole to a role that IS admin. Realistic
# "someone copy-pasted PassRole:*" misconfiguration.
awslocal iam create-role --role-name b9-autoscaler-admin \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
awslocal iam attach-role-policy --role-name b9-autoscaler-admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

awslocal iam create-role --role-name b9-cluster-autoscaler-role \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
awslocal iam put-role-policy --role-name b9-cluster-autoscaler-role \
  --policy-name autoscaler-perms \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["autoscaling:DescribeAutoScalingGroups","autoscaling:SetDesiredCapacity"],"Resource":"*"},{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::000000000000:role/b9-autoscaler-admin"}]}'

# --- Case B (TN expected): efs-csi-controller-sa -- has iam:PassRole,
# but scoped to a Resource ARN that is itself NOT admin. Looks risky
# (PassRole present) but genuinely isn't.
awslocal iam create-role --role-name b9-efs-node-role \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
awslocal iam attach-role-policy --role-name b9-efs-node-role --policy-arn arn:aws:iam::aws:policy/AmazonElasticFileSystemReadOnlyAccess

awslocal iam create-role --role-name b9-efs-csi-controller-role \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
awslocal iam put-role-policy --role-name b9-efs-csi-controller-role \
  --policy-name efs-perms \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["elasticfilesystem:DescribeFileSystems","elasticfilesystem:CreateAccessPoint"],"Resource":"*"},{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::000000000000:role/b9-efs-node-role"}]}'

# --- Case C (TP expected): aws-node -- scoped VPC/ENI perms, PLUS
# sts:AssumeRole into a second role that has PassRole to admin. 3-hop chain.
awslocal iam create-role --role-name b9-shared-jump-role \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:role/b9-aws-node-role"},"Action":"sts:AssumeRole"}]}'
awslocal iam put-role-policy --role-name b9-shared-jump-role \
  --policy-name jump-perms \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::000000000000:role/b9-autoscaler-admin"}]}'

awslocal iam create-role --role-name b9-aws-node-role \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
awslocal iam put-role-policy --role-name b9-aws-node-role \
  --policy-name vpc-perms \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ec2:DescribeNetworkInterfaces","ec2:AttachNetworkInterface"],"Resource":"*"},{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"arn:aws:iam::000000000000:role/b9-shared-jump-role"}]}'

# --- Case D (TN expected): amp-ingest -- scoped AMP ingest perms + group
# membership in a CloudWatch-read-only group. No PassRole, no AssumeRole,
# no admin reachability at all.
awslocal iam create-group --group-name b9-readonly-group
awslocal iam attach-group-policy --group-name b9-readonly-group --policy-arn arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess

awslocal iam create-role --role-name b9-amp-ingest-role \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
awslocal iam put-role-policy --role-name b9-amp-ingest-role \
  --policy-name amp-perms \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["aps:RemoteWrite","aps:GetSeries"],"Resource":"*"}]}'

echo "Benchmark 9 AWS setup complete (4 near-miss cases: A=TP, B=TN, C=TP, D=TN)."
