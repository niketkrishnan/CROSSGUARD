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

## Run and check (copy and paste)

Run from the repository root, in the project's virtual environment (`source venv/bin/activate`), with Docker and Minikube running. The first line loads `benchmarks/common.sh`, which sets the dummy AWS variables for LocalStack, defines the `cleanx` helper and checks the tools.

**Case:** False-positive check: five ServiceAccounts exist, only one has an IRSA annotation to an admin role.

```bash
source benchmarks/common.sh
./benchmarks/reset_environment.sh && cleanx
./benchmarks/bench3/setup_aws.sh 2>&1 | grep -E "complete|rror"
for i in 0 1 2 3 4; do kubectl create serviceaccount bench3-sa-$i -n default; done
kubectl annotate serviceaccount bench3-sa-2 -n default eks.amazonaws.com/role-arn=arn:aws:iam::000000000000:role/b3-admin-role
kubectl apply -f benchmarks/bench3/pods.yaml
privesc-scan --endpoint-url http://localhost:4566 2>&1 | grep -v WARNING
```

**Expected:** 131 nodes, 43 edges, 1 path from `bench3-sa-2` only, risk 6.0. The other four ServiceAccounts are not flagged.

**Web page:** Role ARN `arn:aws:iam::000000000000:role/b3-admin-role`. After Apply fix: 42 edges, 0 paths.
