# Real-World Test: eks-with-istio

## Source
github.com/msfidelis/eks-with-istio
Real production EKS deployment with Istio service mesh.
SA template: helm/sample/templates/service-account.yaml
Risk identified in analysis: iam:PassRole in iam_karpenter.tf

## What we tested
Scenario 1 (MISCONFIGURED): sample-app SA annotated with Karpenter
role (AdministratorAccess) -- models the real risk where an app SA
accidentally receives an infrastructure role ARN.

Scenario 2 (CORRECT): sample-app-scoped SA with S3 app bucket only.

## Result
Paths found: 1 (Scenario 1 only)
Path: sample-app --[irsa_bridge]--> eks-istio-karpenter (risk 6.0)
False positives: 0
Remediation: kubectl annotate serviceaccount sample-app -n istio-sample eks.amazonaws.com/role-arn-

## Template source
helm/sample/templates/service-account.yaml with ARN values substituted
to match LocalStack test environment (standard methodology for
evaluating tools against template-based real-world configurations).
