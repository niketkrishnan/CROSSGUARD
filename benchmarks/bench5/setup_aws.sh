#!/bin/bash
# Benchmark 5 -- false positive control. IRSA annotation exists and
# points to a REAL role, but that role only has scoped S3 read
# permissions -- no path to admin exists. Tool must report 0 paths.
set -e

export AWS_DEFAULT_REGION=us-east-1
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test

awslocal iam create-role --role-name b5-safe-role \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

awslocal iam put-role-policy \
  --role-name b5-safe-role \
  --policy-name s3-read-only \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":"*"}]}'

echo "Benchmark 5 AWS setup complete."
