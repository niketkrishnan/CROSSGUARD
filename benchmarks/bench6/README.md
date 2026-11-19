# Benchmark 6 -- Multiple Paths, Verify Correct Ranking

## Scoping note
The brief's original description (SA->RoleA->RoleB->Admin AND
SA->RoleC->Admin existing simultaneously, branching directly from the
SA) isn't constructible via IRSA, since an IRSA annotation points at
exactly one role. This benchmark instead branches both routes from
that single IRSA-bridged role (b6-role-a), which has two independent
escalation routes onward -- same test of ranking behavior, structurally
valid for real AWS.

## Setup
1. Reset environment: ./benchmarks/reset_environment.sh
2. Run ./benchmarks/bench6/setup_aws.sh
3. kubectl create serviceaccount bench6-sa -n default
4. kubectl annotate serviceaccount bench6-sa -n default eks.amazonaws.com/role-arn=arn:aws:iam::000000000000:role/b6-role-a
5. kubectl apply -f benchmarks/bench6/test-pod.yaml

## Ground truth
Route 1 (2 hops): bench6-sa -> b6-role-a -[PassRole]-> b6-admin-near
Route 2 (3 hops): bench6-sa -> b6-role-a -[PassRole]-> b6-role-b -[AssumeRole]-> b6-admin-far

Expected: 2 paths found, Route 1 ranked higher (the score is the average edge weight, so the
shorter route with the heavier PassRole hop scores higher).

## Actual result (validated live against LocalStack + Minikube)
- 2 paths found
- Route 1 (2 hops): risk score 5.5 -- ranked first, as expected
- Route 2 (3 hops): risk score 4.67 under the default `--semantics strict`
  (5.0 under `legacy`/`annotate`) -- ranked second, as expected
- Strict mode drops the `b6-role-a -[PassRole]-> b6-role-b` edge because
  b6-role-b is trusted only by an AWS principal, so no service can assume
  it. Route 2 is still found through the real `sts:AssumeRole` trust
  (graph: 130 nodes / 47 edges strict vs 52 edges legacy).
- Remediation: a SINGLE recommendation (remove IRSA annotation from
  bench6-sa) correctly breaks BOTH paths at once -- validates the
  global minimum-cut implementation (Module 5) correctly identifies a
  shared bottleneck across multiple paths, rather than recommending
  separate fixes per path

## Expected PMapper output
0 paths (no Kubernetes awareness)

## Running the benchmark

From the repository root, with the project's virtual environment active and Docker and Minikube running.

**Scenario:** Multiple paths, one shared fix: one entry point has a short 2-hop route and a longer 3-hop route to admin.

```bash
source benchmarks/common.sh
./benchmarks/reset_environment.sh && cleanx
./benchmarks/bench6/setup_aws.sh 2>&1 | grep -E "complete|rror"
kubectl create serviceaccount bench6-sa -n default
kubectl annotate serviceaccount bench6-sa -n default eks.amazonaws.com/role-arn=arn:aws:iam::000000000000:role/b6-role-a
kubectl apply -f benchmarks/bench6/test-pod.yaml
privesc-scan --endpoint-url http://localhost:4566 2>&1 | grep -v WARNING
```

**Expected result:** 130 nodes, 47 edges, 2 paths. Short path (2 hops) scores 5.5 and is `potential` (a bare `iam:PassRole`). Long path (3 hops) scores 4.67 and is `confirmed`. One shared fix (remove the IRSA annotation) closes both.

**Web interface:** Role ARN `arn:aws:iam::000000000000:role/b6-role-a`. After Apply fix: 46 edges, 0 paths. The default mode is strict. In `--semantics legacy` the long path scores 5.0 and there are 52 edges, because a PassRole edge to a role no service can assume is kept.
