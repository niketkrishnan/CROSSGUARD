# OWASP EKS Goat Assessment

## Finding: EKS Goat does not test IRSA misconfiguration

After reviewing the full deployment scripts and Kubernetes manifests,
OWASP EKS Goat's attack scenarios are based on:
1. ECR image backdooring (supply chain attack via Docker image repackaging)
2. IMDSv2 credential theft from EC2 worker nodes
3. Container escape via privileged pod configurations

The ServiceAccount (peachycloudsecurity-sa) in EKS Goat has NO IRSA
annotation (eks.amazonaws.com/role-arn) and the deploy script contains
zero OIDC/IRSA configuration. The IAM credentials used in its attack
scenario come from EC2 instance profiles on worker nodes, not from
IRSA-annotated ServiceAccounts.

## Decision: Not deployed

Running our tool against EKS Goat would produce 0 cross-layer paths
-- not because the environment is secure (it isn't), but because its
attack surface is ECR/IMDSv2/container escape, entirely outside our
threat model (IRSA-based cross-layer escalation via ServiceAccount
annotation).

Deploying it on real AWS would cost ~$5 and validate nothing relevant
to our tool's novel contributions. This is documented as a deliberate,
reasoned scoping decision, not an oversight.

## Alternative: Minimal real EKS validation (recommended)

A more meaningful real-AWS validation would be a minimal EKS cluster
with one deliberately IRSA-misconfigured ServiceAccount -- directly
testing C2 (IRSA bridge edge detection) against real AWS OIDC/STS
federation rather than LocalStack's approximation. This would cost
the same (~$2-5) and directly validate the tool's core contribution
on real infrastructure. This is deferred pending AWS account setup.
