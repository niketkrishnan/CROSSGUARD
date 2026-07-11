# Real-World Test: AWS Load Balancer Controller

## Source
github.com/kubernetes-sigs/aws-load-balancer-controller
One of the most widely deployed Kubernetes controllers for AWS EKS.
RBAC structure taken directly from the official repo.

## What we tested
Two deployment scenarios side by side:

Scenario 1 (MISCONFIGURED):
  aws-load-balancer-controller SA annotated with an over-privileged
  IAM role (AdministratorAccess). This models the real-world mistake
  of using an admin role for convenience during setup -- a pattern
  documented in Unit 42 cloud threat reports.

Scenario 2 (CORRECTLY CONFIGURED):
  aws-load-balancer-controller-safe SA annotated with a correctly
  scoped role (ELB read-only permissions only).

## Result
Paths found: 1 (Scenario 1 only)
Path: aws-load-balancer-controller --[irsa_bridge]--> aws-load-balancer-controller (admin)
Risk score: 6.0
False positives: 0 (Scenario 2 correctly produced no path)

Remediation: Remove IRSA annotation from aws-lb-controller/aws-load-balancer-controller
Command: kubectl annotate serviceaccount aws-load-balancer-controller \
         -n aws-lb-controller eks.amazonaws.com/role-arn-

## Significance
The aws-load-balancer-controller is deployed in millions of EKS clusters
worldwide. Our tool correctly distinguishes between a misconfigured
deployment (admin role) and a correctly-scoped deployment (ELB-only),
with 0 false positives, using the real project's actual RBAC structure.
This demonstrates the tool works against genuine production Kubernetes
configurations, not just synthetic benchmarks.
