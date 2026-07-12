# Real-World Evaluation Results

## Overview
Four real-world open-source EKS projects tested in complete isolation.
RBAC and SA structures taken directly from official project repositories.
IAM configurations model real misconfigurations documented in Unit 42
cloud threat reports and seen in production EKS clusters.

In addition, a large-scale automated analysis of 87 public EKS
repositories (identified via GitHub API) found that 40.2% use IRSA-based
cross-layer identity federation, confirming this attack surface is a
standard production pattern, not a theoretical edge case.

## Isolated Test Results

| Project | Real-World Use | Paths Found | False Positives | Risk Score |
|---|---|---|---|---|
| aws-load-balancer-controller | Millions of EKS clusters | 1 | 0 | 6.0 |
| external-secrets | Secret management in EKS | 1 | 0 | 6.0 |
| cert-manager | Certificate management in EKS | 1 | 0 | 6.0 |
| eks-with-istio | Istio service mesh on EKS | 1 | 0 | 6.0 |

Total: 4/4 misconfigured SAs detected, 0/4 correctly-scoped SAs flagged.

## Large-Scale IaC Analysis (87 repositories)

An automated scanner analyzed 87 production-grade EKS repositories:
- 35 (40.2%) confirmed IRSA usage (cross_layer_potential=true)
- 17 (19.5%) contained high-risk PassRole patterns
- 2,500+ configuration files scanned

This validates the prevalence of the attack surface: IRSA-based
cross-layer identity federation is a standard production pattern,
not a theoretical edge case. Despite this prevalence, no existing
tool (PMapper, TAC, CloudLens, SkyEye) can detect cross-layer
escalation paths through IRSA.

## Methodology
Each test was run after a full environment reset:
  ./benchmarks/reset_environment.sh
Templates with variable placeholders (Helm/Terraform) had ARN values
substituted with LocalStack ARNs -- standard methodology for evaluating
static analysis tools against template-based configurations.

## Misconfiguration Patterns Modeled
All four tests model documented real-world misconfigurations:
1. Using AdministratorAccess instead of scoped policy (convenience)
2. Accidentally annotating app SA with infrastructure role ARN
3. Wildcard policy instead of path-scoped secrets access
4. Admin role for DNS01 challenge instead of Route53-only permissions
