# Benchmark 5 -- No Path Exists (False Positive Control)

## Purpose
The most important benchmark for the false-positive-rate claim. IRSA
annotation exists and correctly resolves to a real role, but that role
has only scoped S3 read-only permissions -- no escalation path exists.
The tool must report 0 paths.

## Setup
1. Reset environment: ./benchmarks/reset_environment.sh
2. Run ./benchmarks/bench5/setup_aws.sh
3. kubectl create serviceaccount bench5-sa -n default
4. kubectl annotate serviceaccount bench5-sa -n default eks.amazonaws.com/role-arn=arn:aws:iam::000000000000:role/b5-safe-role
5. kubectl apply -f benchmarks/bench5/test-pod.yaml

## Ground truth
bench5-pod -> bench5-sa -> IRSA bridge -> b5-safe-role (s3:GetObject,
s3:ListBucket only -- no path onward to admin).

Expected: 0 cross-layer escalation paths.

## Actual result (validated live against LocalStack + Minikube)
- IRSA mapping correctly detected: 1 mapping found (proves the bridge
  itself is not the limiting factor)
- 0 cross-layer escalation paths reported
- This confirms the tool does not hallucinate a path just because an
  IRSA annotation exists -- it correctly evaluates what the target
  role can actually do

## Expected PMapper output
0 paths (but for an entirely different reason -- PMapper cannot see
Kubernetes or the IRSA annotation at all, so this "correct" result is
coincidental, not evidence of correct analysis)

## Running the benchmark

From the repository root, with the project's virtual environment active and Docker and Minikube running.

**Scenario:** Negative control: the IRSA link is real and valid, but the role only has S3 read access, so no route to admin exists.

```bash
source benchmarks/common.sh
./benchmarks/reset_environment.sh && cleanx
./benchmarks/bench5/setup_aws.sh 2>&1 | grep -E "complete|rror"
kubectl create serviceaccount bench5-sa -n default
kubectl annotate serviceaccount bench5-sa -n default eks.amazonaws.com/role-arn=arn:aws:iam::000000000000:role/b5-safe-role
kubectl apply -f benchmarks/bench5/test-pod.yaml
privesc-scan --endpoint-url http://localhost:4566 2>&1 | grep -v WARNING
```

**Expected result:** 127 nodes, 43 edges, 0 paths. Nothing is reported because nothing is wrong.

**Web interface:** Role ARN `arn:aws:iam::000000000000:role/b5-safe-role`. No Apply fix button. Click "Show all" to see `bench5-sa` connected to `b5-safe-role`.
