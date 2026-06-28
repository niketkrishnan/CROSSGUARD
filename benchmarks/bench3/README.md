# Benchmark 3 -- Multiple ServiceAccounts, Only One Vulnerable

## Purpose
False-positive check on the Kubernetes side. 5 ServiceAccounts (and 5
pods, one per SA) exist in the cluster. Only bench3-sa-2 has the IRSA
annotation. The tool must report exactly 1 path and must not
hallucinate paths from the other 4 clean ServiceAccounts.

## Setup
1. Reset environment: ./benchmarks/reset_environment.sh
2. Run ./benchmarks/bench3/setup_aws.sh
3. Create 5 ServiceAccounts: bench3-sa-0 through bench3-sa-4
4. Annotate only bench3-sa-2: kubectl annotate serviceaccount bench3-sa-2 -n default eks.amazonaws.com/role-arn=arn:aws:iam::000000000000:role/b3-admin-role
5. kubectl apply -f benchmarks/bench3/pods.yaml

## Ground truth attack path

bench3-pod-2 (Pod)
  -> runs as bench3-sa-2 (ServiceAccount)
    -> IRSA bridge -> b3-admin-role (AdministratorAccess)

1 hop. Cross-layer: yes.
bench3-sa-0, bench3-sa-1, bench3-sa-3, bench3-sa-4 have NO escalation
path and must NOT appear in tool output.

## Actual tool output (validated live)
- Exactly 1 cross-layer escalation path found
- Entry point correctly identified: bench3-sa-2 (and resolved to the
  actual running pod bench3-pod-2 via find_pods_for_service_account)
- 0 false positives from the other 4 ServiceAccounts
- Risk score: 6.0
- Remediation: remove IRSA annotation from bench3-sa-2

## Expected PMapper output
0 paths (no Kubernetes awareness at all -- cannot even see that 5
ServiceAccounts or 5 pods exist, let alone distinguish the vulnerable one)
