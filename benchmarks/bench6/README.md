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

Expected: 2 paths found, Route 1 ranked higher (fewer hops = higher risk score).

## Actual result (validated live against LocalStack + Minikube)
- 2 paths found
- Route 1 (2 hops): risk score 5.5 -- ranked first, as expected
- Route 2 (3 hops): risk score 5.0 -- ranked second, as expected
- Remediation: a SINGLE recommendation (remove IRSA annotation from
  bench6-sa) correctly breaks BOTH paths at once -- validates the
  global minimum-cut implementation (Module 5) correctly identifies a
  shared bottleneck across multiple paths, rather than recommending
  separate fixes per path

## Expected PMapper output
0 paths (no Kubernetes awareness)
