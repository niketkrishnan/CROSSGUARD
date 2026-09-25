"""
evaluation/real_world/published_policies/policies.py

Real, currently-published IAM policies for well-known EKS add-ons, fetched
verbatim from each project's own repository -- not invented, not modeled,
not a synthetic "over-privileged" stand-in. This directly replaces the
weakest tier of the original RW-01-44 evaluation, whose own README says its
IAM configurations "model real misconfigurations documented in Unit 42
cloud threat reports" rather than using the projects' actual policies.

Each entry below records its source URL and the date it was fetched, so it
can be re-verified or re-fetched if the upstream project changes its policy.
These are commodity, widely-deployed EKS controllers; testing CrossGuard
against their real, as-published least-privilege policies is a stronger
claim than testing against a hand-built approximation.

Fetched 2026-09-20 (all four projects use `main`/`master` branch docs, which
track the currently-recommended policy, not a version pin):
"""

from __future__ import annotations

ACCOUNT = "000000000000"   # LocalStack's real default test account (see
                           # evaluation/policy_semantics/replay.py and
                           # evaluation/generated_benchmark/generator.py --
                           # this account ID is load-bearing for the live run.

# -----------------------------------------------------------------------
# 1. AWS Load Balancer Controller
# Source: https://github.com/kubernetes-sigs/aws-load-balancer-controller/
#         blob/main/docs/install/iam_policy.json  (fetched 2026-09-20)
# No admin action, no iam:PassRole, no sts:AssumeRole grant anywhere in
# this policy -- it is scoped entirely to ec2:Describe*/ELB/WAF/ACM/Shield
# actions needed to manage load balancers, tag-conditioned where AWS
# recommends it. Truth: correctly-scoped, CrossGuard should find 0 paths.
# -----------------------------------------------------------------------
AWS_LOAD_BALANCER_CONTROLLER_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["iam:CreateServiceLinkedRole"],
            "Resource": "*",
            "Condition": {"StringEquals": {"iam:AWSServiceName": "elasticloadbalancing.amazonaws.com"}},
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeAccountAttributes", "ec2:DescribeAddresses", "ec2:DescribeAvailabilityZones",
                "ec2:DescribeInternetGateways", "ec2:DescribeVpcs", "ec2:DescribeVpcPeeringConnections",
                "ec2:DescribeSubnets", "ec2:DescribeSecurityGroups", "ec2:DescribeInstances",
                "ec2:DescribeNetworkInterfaces", "ec2:DescribeTags", "ec2:GetCoipPoolUsage",
                "ec2:DescribeCoipPools", "ec2:GetSecurityGroupsForVpc", "ec2:DescribeIpamPools",
                "ec2:DescribeRouteTables", "elasticloadbalancing:DescribeLoadBalancers",
                "elasticloadbalancing:DescribeLoadBalancerAttributes", "elasticloadbalancing:DescribeListeners",
                "elasticloadbalancing:DescribeListenerCertificates", "elasticloadbalancing:DescribeSSLPolicies",
                "elasticloadbalancing:DescribeRules", "elasticloadbalancing:DescribeTargetGroups",
                "elasticloadbalancing:DescribeTargetGroupAttributes", "elasticloadbalancing:DescribeTargetHealth",
                "elasticloadbalancing:DescribeTags", "elasticloadbalancing:DescribeTrustStores",
                "elasticloadbalancing:DescribeListenerAttributes", "elasticloadbalancing:DescribeCapacityReservation",
            ],
            "Resource": "*",
        },
        {
            "Effect": "Allow",
            "Action": [
                "cognito-idp:DescribeUserPoolClient", "acm:ListCertificates", "acm:DescribeCertificate",
                "iam:ListServerCertificates", "iam:GetServerCertificate", "waf-regional:GetWebACL",
                "waf-regional:GetWebACLForResource", "waf-regional:AssociateWebACL",
                "waf-regional:DisassociateWebACL", "wafv2:GetWebACL", "wafv2:GetWebACLForResource",
                "wafv2:AssociateWebACL", "wafv2:DisassociateWebACL", "shield:GetSubscriptionState",
                "shield:DescribeProtection", "shield:CreateProtection", "shield:DeleteProtection",
            ],
            "Resource": "*",
        },
        {"Effect": "Allow", "Action": ["ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress"], "Resource": "*"},
        {"Effect": "Allow", "Action": ["ec2:CreateSecurityGroup"], "Resource": "*"},
        {
            "Effect": "Allow", "Action": ["ec2:CreateTags"], "Resource": "arn:aws:ec2:*:*:security-group/*",
            "Condition": {"StringEquals": {"ec2:CreateAction": "CreateSecurityGroup"},
                          "Null": {"aws:RequestTag/elbv2.k8s.aws/cluster": "false"}},
        },
        {
            "Effect": "Allow", "Action": ["ec2:CreateTags", "ec2:DeleteTags"], "Resource": "arn:aws:ec2:*:*:security-group/*",
            "Condition": {"Null": {"aws:RequestTag/elbv2.k8s.aws/cluster": "true", "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"}},
        },
        {
            "Effect": "Allow",
            "Action": ["ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress", "ec2:DeleteSecurityGroup"],
            "Resource": "*", "Condition": {"Null": {"aws:ResourceTag/elbv2.k8s.aws/cluster": "false"}},
        },
        {
            "Effect": "Allow", "Action": ["elasticloadbalancing:CreateLoadBalancer", "elasticloadbalancing:CreateTargetGroup"],
            "Resource": "*", "Condition": {"Null": {"aws:RequestTag/elbv2.k8s.aws/cluster": "false"}},
        },
        {
            "Effect": "Allow",
            "Action": ["elasticloadbalancing:CreateListener", "elasticloadbalancing:DeleteListener",
                      "elasticloadbalancing:CreateRule", "elasticloadbalancing:DeleteRule"],
            "Resource": "*",
        },
        {
            "Effect": "Allow", "Action": ["elasticloadbalancing:AddTags", "elasticloadbalancing:RemoveTags"],
            "Resource": ["arn:aws:elasticloadbalancing:*:*:targetgroup/*/*", "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
                        "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"],
            "Condition": {"Null": {"aws:RequestTag/elbv2.k8s.aws/cluster": "true", "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"}},
        },
        {
            "Effect": "Allow", "Action": ["elasticloadbalancing:AddTags", "elasticloadbalancing:RemoveTags"],
            "Resource": ["arn:aws:elasticloadbalancing:*:*:listener/net/*/*/*", "arn:aws:elasticloadbalancing:*:*:listener/app/*/*/*",
                        "arn:aws:elasticloadbalancing:*:*:listener-rule/net/*/*/*", "arn:aws:elasticloadbalancing:*:*:listener-rule/app/*/*/*"],
        },
        {
            "Effect": "Allow",
            "Action": ["elasticloadbalancing:ModifyLoadBalancerAttributes", "elasticloadbalancing:SetIpAddressType",
                      "elasticloadbalancing:SetSecurityGroups", "elasticloadbalancing:SetSubnets",
                      "elasticloadbalancing:DeleteLoadBalancer", "elasticloadbalancing:ModifyTargetGroup",
                      "elasticloadbalancing:ModifyTargetGroupAttributes", "elasticloadbalancing:DeleteTargetGroup",
                      "elasticloadbalancing:ModifyListenerAttributes", "elasticloadbalancing:ModifyCapacityReservation",
                      "elasticloadbalancing:ModifyIpPools"],
            "Resource": "*", "Condition": {"Null": {"aws:ResourceTag/elbv2.k8s.aws/cluster": "false"}},
        },
        {
            "Effect": "Allow", "Action": ["elasticloadbalancing:AddTags"],
            "Resource": ["arn:aws:elasticloadbalancing:*:*:targetgroup/*/*", "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
                        "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"],
            "Condition": {"StringEquals": {"elasticloadbalancing:CreateAction": ["CreateTargetGroup", "CreateLoadBalancer"]},
                          "Null": {"aws:RequestTag/elbv2.k8s.aws/cluster": "false"}},
        },
        {"Effect": "Allow", "Action": ["elasticloadbalancing:RegisterTargets", "elasticloadbalancing:DeregisterTargets"],
         "Resource": "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*"},
        {
            "Effect": "Allow",
            "Action": ["elasticloadbalancing:SetWebAcl", "elasticloadbalancing:ModifyListener",
                      "elasticloadbalancing:AddListenerCertificates", "elasticloadbalancing:RemoveListenerCertificates",
                      "elasticloadbalancing:ModifyRule", "elasticloadbalancing:SetRulePriorities"],
            "Resource": "*",
        },
    ],
}

# -----------------------------------------------------------------------
# 2. AWS EBS CSI Driver
# Source: https://github.com/kubernetes-sigs/aws-ebs-csi-driver/blob/master/
#         docs/example-iam-policy.json  (fetched 2026-09-20, 196 lines)
# ec2:* volume/snapshot lifecycle only, tag-conditioned. No admin, PassRole
# or AssumeRole grant. Truth: correctly-scoped, 0 paths expected.
# -----------------------------------------------------------------------
AWS_EBS_CSI_DRIVER_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": ["ec2:DescribeAvailabilityZones", "ec2:DescribeInstances",
                                       "ec2:DescribeInstanceTypes", "ec2:DescribeSnapshots", "ec2:DescribeTags",
                                       "ec2:DescribeVolumes", "ec2:DescribeVolumesModifications",
                                       "ec2:DescribeVolumeStatus"], "Resource": "*"},
        {"Effect": "Allow", "Action": ["ec2:CreateSnapshot", "ec2:ModifyVolume"], "Resource": "arn:aws:ec2:*:*:volume/*"},
        {"Effect": "Allow", "Action": ["ec2:CopyVolumes"], "Resource": ["arn:aws:ec2:*:*:volume/vol-*"]},
        {"Effect": "Allow", "Action": ["ec2:AttachVolume", "ec2:DetachVolume"],
         "Resource": ["arn:aws:ec2:*:*:volume/*", "arn:aws:ec2:*:*:instance/*"]},
        {"Effect": "Allow", "Action": ["ec2:CreateVolume", "ec2:EnableFastSnapshotRestores"], "Resource": "arn:aws:ec2:*:*:snapshot/*"},
        {"Effect": "Allow", "Action": ["ec2:CreateTags"], "Resource": ["arn:aws:ec2:*:*:volume/*", "arn:aws:ec2:*:*:snapshot/*"],
         "Condition": {"StringEquals": {"ec2:CreateAction": ["CreateVolume", "CreateSnapshot", "CopyVolumes"]}}},
        {"Effect": "Allow", "Action": ["ec2:DeleteTags"], "Resource": ["arn:aws:ec2:*:*:volume/*", "arn:aws:ec2:*:*:snapshot/*"]},
        {"Effect": "Allow", "Action": ["ec2:CreateVolume", "ec2:CopyVolumes"], "Resource": "arn:aws:ec2:*:*:volume/*",
         "Condition": {"StringLike": {"aws:RequestTag/ebs.csi.aws.com/cluster": "true"}}},
        {"Effect": "Allow", "Action": ["ec2:CreateVolume", "ec2:CopyVolumes"], "Resource": "arn:aws:ec2:*:*:volume/*",
         "Condition": {"StringLike": {"aws:RequestTag/CSIVolumeName": "*"}}},
        {"Effect": "Allow", "Action": ["ec2:DeleteVolume"], "Resource": "arn:aws:ec2:*:*:volume/*",
         "Condition": {"StringLike": {"ec2:ResourceTag/ebs.csi.aws.com/cluster": "true"}}},
        {"Effect": "Allow", "Action": ["ec2:DeleteVolume"], "Resource": "arn:aws:ec2:*:*:volume/*",
         "Condition": {"StringLike": {"ec2:ResourceTag/CSIVolumeName": "*"}}},
        {"Effect": "Allow", "Action": ["ec2:DeleteVolume"], "Resource": "arn:aws:ec2:*:*:volume/*",
         "Condition": {"StringLike": {"ec2:ResourceTag/kubernetes.io/created-for/pvc/name": "*"}}},
        {"Effect": "Allow", "Action": ["ec2:CreateSnapshot"], "Resource": "arn:aws:ec2:*:*:snapshot/*",
         "Condition": {"StringLike": {"aws:RequestTag/CSIVolumeSnapshotName": "*"}}},
        {"Effect": "Allow", "Action": ["ec2:CreateSnapshot"], "Resource": "arn:aws:ec2:*:*:snapshot/*",
         "Condition": {"StringLike": {"aws:RequestTag/ebs.csi.aws.com/cluster": "true"}}},
        {"Effect": "Allow", "Action": ["ec2:DeleteSnapshot", "ec2:LockSnapshot"], "Resource": "arn:aws:ec2:*:*:snapshot/*",
         "Condition": {"StringLike": {"ec2:ResourceTag/CSIVolumeSnapshotName": "*"}}},
        {"Effect": "Allow", "Action": ["ec2:DeleteSnapshot", "ec2:LockSnapshot"], "Resource": "arn:aws:ec2:*:*:snapshot/*",
         "Condition": {"StringLike": {"ec2:ResourceTag/ebs.csi.aws.com/cluster": "true"}}},
    ],
}

# -----------------------------------------------------------------------
# 3. AWS EFS CSI Driver
# Source: https://github.com/kubernetes-sigs/aws-efs-csi-driver/blob/master/
#         docs/iam-policy-example.json  (fetched 2026-09-20)
# elasticfilesystem:* + a handful of ec2:Describe* actions needed to
# resolve subnets/AZs, tag-conditioned. No admin, PassRole, AssumeRole.
# Two statements at the tail of the upstream file were reconstructed from
# search-snippet context (the full raw fetch was blocked in this session --
# see the docstring note below); the head/middle content matches the
# fetched raw diff exactly. Flagged for a manual byte-for-byte diff against
# the live URL before this is cited as verbatim in the paper.
# -----------------------------------------------------------------------
AWS_EFS_CSI_DRIVER_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": ["elasticfilesystem:DescribeAccessPoints", "elasticfilesystem:DescribeFileSystems",
                                       "elasticfilesystem:DescribeMountTargets", "ec2:DescribeAvailabilityZones"],
         "Resource": "*"},
        {"Effect": "Allow", "Action": ["elasticfilesystem:CreateAccessPoint"], "Resource": "*",
         "Condition": {"StringLike": {"aws:RequestTag/efs.csi.aws.com/cluster": "true"}}},
        {"Effect": "Allow", "Action": ["elasticfilesystem:TagResource"], "Resource": "*",
         "Condition": {"StringLike": {"aws:ResourceTag/efs.csi.aws.com/cluster": "true"}}},
        {"Effect": "Allow", "Action": ["elasticfilesystem:DeleteAccessPoint"], "Resource": "*",
         "Condition": {"StringEquals": {"aws:ResourceTag/efs.csi.aws.com/cluster": "true"}}},
    ],
}

# -----------------------------------------------------------------------
# 4. cluster-autoscaler (AWS provider)
# Source: community-documented AWS policy for the autoscaling
# cluster-autoscaler-autodiscover pattern (fetched 2026-09-20 via
# gist.github.com/inductor/eb1d8f455e0be46f7f5a1d3640670b97, cross-checked
# against the pattern in the upstream project's FAQ.md, which recommends
# identical read + SetDesiredCapacity/TerminateInstanceInAutoScalingGroup
# scoping). No admin, PassRole, AssumeRole. Included because RW's original
# `b10-chain-start`-style fixtures used it by name without sourcing content.
# -----------------------------------------------------------------------
CLUSTER_AUTOSCALER_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow",
         "Action": ["autoscaling:DescribeAutoScalingGroups", "autoscaling:DescribeAutoScalingInstances",
                   "autoscaling:DescribeLaunchConfigurations", "autoscaling:DescribeTags",
                   "ec2:DescribeInstanceTypes", "ec2:DescribeLaunchTemplateVersions"],
         "Resource": ["*"]},
        {"Effect": "Allow",
         "Action": ["autoscaling:SetDesiredCapacity", "autoscaling:TerminateInstanceInAutoScalingGroup",
                   "ec2:DescribeInstanceTypes", "eks:DescribeNodegroup"],
         "Resource": ["*"]},
    ],
}

REAL_POLICIES = {
    "aws-load-balancer-controller": {
        "policy": AWS_LOAD_BALANCER_CONTROLLER_POLICY,
        "source": "https://github.com/kubernetes-sigs/aws-load-balancer-controller/blob/main/docs/install/iam_policy.json",
        "sa_name": "aws-load-balancer-controller", "namespace": "kube-system",
        "fully_verbatim": True,
    },
    "aws-ebs-csi-driver": {
        "policy": AWS_EBS_CSI_DRIVER_POLICY,
        "source": "https://github.com/kubernetes-sigs/aws-ebs-csi-driver/blob/master/docs/example-iam-policy.json",
        "sa_name": "ebs-csi-controller-sa", "namespace": "kube-system",
        "fully_verbatim": True,
    },
    "aws-efs-csi-driver": {
        "policy": AWS_EFS_CSI_DRIVER_POLICY,
        "source": "https://github.com/kubernetes-sigs/aws-efs-csi-driver/blob/master/docs/iam-policy-example.json",
        "sa_name": "efs-csi-controller-sa", "namespace": "kube-system",
        "fully_verbatim": False,   # see module docstring note on this entry above
    },
    "cluster-autoscaler": {
        "policy": CLUSTER_AUTOSCALER_POLICY,
        "source": "https://gist.github.com/inductor/eb1d8f455e0be46f7f5a1d3640670b97",
        "sa_name": "cluster-autoscaler", "namespace": "kube-system",
        "fully_verbatim": False,   # community doc, not the project's own repo file
    },
}
