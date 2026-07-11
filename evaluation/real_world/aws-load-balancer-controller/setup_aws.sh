#!/bin/bash
# Real-world test: AWS Load Balancer Controller IAM configuration
# Based on the actual IAM policy documented by AWS for this controller:
# https://docs.aws.amazon.com/eks/latest/userguide/lbc-helm.html
set -e

export AWS_DEFAULT_REGION=us-east-1
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test

# The real controller role -- in production this would have the full
# AWSLoadBalancerControllerIAMPolicy attached (EC2, ELB permissions).
# For our test we use AdministratorAccess to model the worst case:
# what if this role was over-privileged (a real misconfiguration seen
# in the wild when operators use admin roles for convenience)?
awslocal iam create-role --role-name aws-load-balancer-controller \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

awslocal iam attach-role-policy \
  --role-name aws-load-balancer-controller \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# A second role -- scoped correctly (read-only ELB access)
# This represents what the role SHOULD have in a secure config
awslocal iam create-role --role-name aws-load-balancer-controller-safe \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

awslocal iam put-role-policy \
  --role-name aws-load-balancer-controller-safe \
  --policy-name elb-read-only \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": [
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeTargetGroups",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets"
      ],
      "Resource": "*"
    }]
  }'

echo "AWS IAM setup complete:"
echo "  aws-load-balancer-controller (OVER-PRIVILEGED: AdministratorAccess)"
echo "  aws-load-balancer-controller-safe (correctly scoped: ELB read-only)"
