# Kubernetes Goat Evaluation

## Dataset
Kubernetes Goat (github.com/madhuakula/kubernetes-goat)
A deliberately vulnerable Kubernetes environment with multiple
misconfiguration scenarios. We deployed the insecure-rbac scenario
against our existing Minikube cluster, which creates:
- ServiceAccount "superadmin" in kube-system namespace
- ClusterRoleBinding granting superadmin the cluster-admin ClusterRole
  (full Kubernetes API access)

We additionally annotated the superadmin SA with an IRSA bridge to a
LocalStack admin role (goat-admin-role with AdministratorAccess) to
model the realistic combined scenario where a cluster admin
accidentally or maliciously over-annotates an already-privileged SA.

## Scenario: Compounded Privilege Escalation

superadmin (kube-system) is dangerous at TWO layers simultaneously:
1. K8s layer: ClusterRoleBinding -> cluster-admin (full K8s API access)
2. AWS layer: IRSA annotation -> goat-admin-role (AdministratorAccess)

An attacker who compromises any pod running as this ServiceAccount
obtains both full Kubernetes control AND full AWS administrator access
in a single exploitation step. No chaining required -- both privileges
are immediately available via the SA token.

## Our Tool Results

Graph: 128 nodes, 44 edges.
Cross-layer escalation paths found: 1.
Path: superadmin --[irsa_bridge]--> goat-admin-role
Risk score: 6.0 (highest possible -- 1 hop, irsa_bridge edge, cross-layer)
Remediation: Remove IRSA annotation from kube-system/superadmin
  Command: kubectl annotate serviceaccount superadmin -n kube-system
           eks.amazonaws.com/role-arn-

## Significance for the Paper

This scenario illustrates why the cross-layer perspective matters even
when K8s-only tools (like EPScan) might flag the cluster-admin binding
as excessive: EPScan would correctly report the RBAC over-permission,
but cannot see that this SA also has an AWS dimension via IRSA. Our
tool surfaces the complete, compound risk in a single unified finding,
with a precise remediation that addresses the cross-layer exposure
specifically (removing the IRSA annotation, leaving the K8s-side RBAC
remediation as a separate, independently-documented concern).

## PMapper Results (on the same LocalStack environment)
PMapper sees: 1 role (goat-admin-role), correctly identified as admin.
PMapper privesc output: "role/goat-admin-role is an administrative principal"
PMapper finds 0 escalation paths -- it cannot see superadmin, the
ClusterRoleBinding, or the IRSA annotation at all.

## Coverage of All 15 Kubernetes Goat Scenarios

Kubernetes Goat contains 15 scenarios. We reviewed all 15 and
classified them by relevance to our tool's threat model (cross-layer
K8s RBAC + AWS IAM privilege escalation via IRSA):

Relevant and tested:
- insecure-rbac: ServiceAccount + ClusterRoleBinding -> cluster-admin.
  IRSA bridge added to model realistic combined scenario. TESTED.
  Result: 1 cross-layer path found, risk score 6.0.

Not relevant to our tool (different attack surface):
- batch-check: Job with no serviceAccountName, default SA, no RBAC
- build-code: CI/CD code injection via source code
- cache-store: Redis/Memcached misconfiguration
- docker-bench-security: Docker daemon security benchmarks
- health-check: Application health endpoint exposure
- hidden-in-layers: Secrets embedded in container image layers
- hunger-check: Resource exhaustion / CPU throttling
- internal-proxy: SSRF via internal proxy endpoints
- kube-bench-security: CIS Kubernetes benchmark node/master checks
- kubernetes-goat-home: Dashboard/home page deployment
- kyverno-namespace-exec-block: Admission controller policy, not RBAC
- metadata-db: Cloud metadata API (IMDS) abuse via Helm chart
- poor-registry: Insecure container registry access
- system-monitor: Host-level monitoring with privileged container

Our tool's threat model covers cross-layer identity-based escalation
(K8s RBAC + AWS IAM + IRSA). 14 of 15 Kubernetes Goat scenarios target
entirely different attack surfaces (network, image, host, resource).
The 1 relevant scenario (insecure-rbac) was fully tested and produced
a real finding. This is correct scoping, not incomplete coverage.
