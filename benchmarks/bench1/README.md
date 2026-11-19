# Benchmark 1 — Simple IRSA Chain (2 hops)

## Setup
1. Start LocalStack: `docker run -d --name localstack -p 4566:4566 localstack/localstack:4.14.0`
2. Run `./setup_aws.sh` to create the AWS side (admin-role + low-priv-user)
3. Run: `kubectl create serviceaccount vulnerable-sa -n default`
4. Run: `kubectl annotate serviceaccount vulnerable-sa -n default eks.amazonaws.com/role-arn=arn:aws:iam::000000000000:role/admin-role`
5. Apply `test-pod.yaml`: `kubectl apply -f test-pod.yaml`

## Ground truth attack path

test-pod (Pod)
  -> runs as vulnerable-sa (ServiceAccount)
    -> IRSA bridge -> arn:aws:iam::000000000000:role/admin-role
      -> AdministratorAccess (full AWS admin)

2 hops. Cross-layer: yes (starts in K8s, ends in AWS).

## Expected tool output
- 1 cross-layer escalation path found
- Entry point: test-pod / vulnerable-sa
- Remediation: remove IRSA annotation from vulnerable-sa

## Expected PMapper output
0 paths (PMapper has no Kubernetes awareness, cannot see this path at all)

## Run and check (copy and paste)

Run from the repository root, in the project's virtual environment (`source venv/bin/activate`), with Docker and Minikube running. The first line loads `benchmarks/common.sh`, which sets the dummy AWS variables for LocalStack, defines the `cleanx` helper and checks the tools.

**Case:** Single hop, direct escalation: one ServiceAccount is wired by IRSA straight to a role with full admin.

```bash
source benchmarks/common.sh
./benchmarks/reset_environment.sh && cleanx
./benchmarks/bench1/setup_aws.sh 2>&1 | grep -E "complete|rror"
kubectl create serviceaccount vulnerable-sa -n default
kubectl annotate serviceaccount vulnerable-sa -n default eks.amazonaws.com/role-arn=arn:aws:iam::000000000000:role/admin-role
kubectl apply -f benchmarks/bench1/test-pod.yaml
privesc-scan --endpoint-url http://localhost:4566 2>&1 | grep -v WARNING
```

**Expected:** 128 nodes, 43 edges, 1 path (`vulnerable-sa` -> `admin-role`), 1 hop, risk 6.0, confirmed. The recommended fix removes the IRSA annotation.

**Web page:** Role ARN `arn:aws:iam::000000000000:role/admin-role`. After Apply fix the page re-scans: 42 edges, 0 paths, "Fix verified: 1 -> 0".
