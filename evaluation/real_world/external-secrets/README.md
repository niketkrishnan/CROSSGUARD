# Real-World Test: External Secrets Operator

## Source
github.com/external-secrets/external-secrets
One of the most widely deployed secret management controllers for EKS.
RBAC structure taken from deploy/charts/external-secrets/templates/.

## What we tested
Two deployment scenarios:

Scenario 1 (MISCONFIGURED):
  external-secrets SA with AdministratorAccess -- models the common
  real-world mistake of using a wildcard policy instead of scoping
  to specific secret paths.

Scenario 2 (CORRECTLY CONFIGURED):
  external-secrets-scoped SA with access restricted to
  secretsmanager:GetSecretValue on arn:.../myapp/* only.

## Result (run alongside aws-load-balancer-controller test)
Total paths found: 2 (one per misconfigured controller)
- aws-load-balancer-controller --[irsa_bridge]--> aws-load-balancer-controller (risk 6.0)
- external-secrets --[irsa_bridge]--> external-secrets-operator (risk 6.0)
False positives: 0

The tool correctly scanned BOTH namespaces simultaneously and produced
TWO separate remediation commands -- one per vulnerable controller.
The two correctly-scoped SAs produced zero false positive paths.

## Significance
This models a realistic multi-controller EKS cluster where a security
team needs to audit ALL deployed workloads at once. CrossGuard
correctly processes multiple namespaces, multiple IRSA bridges, and
multiple real-world controller configurations in a single scan.
