# Benchmark 8 -- Two Entry Points, One Shared PassRole Fix

## Setup
```bash
./benchmarks/reset_environment.sh
./benchmarks/bench8/setup_aws.sh
for i in 1 2; do
  kubectl create serviceaccount bench8-sa-$i -n default
  kubectl annotate serviceaccount bench8-sa-$i -n default \
    eks.amazonaws.com/role-arn=arn:aws:iam::000000000000:role/b8-role-shared
done
privesc-scan --endpoint-url http://localhost:4566 --semantics legacy
```
Run with `--semantics legacy`: this benchmark predates the IRSA trust check, and under the default `strict`
mode the tool drops the IRSA edges (the role has an EC2 trust) and reports no path.

## Ground truth
`bench8-sa-1` and `bench8-sa-2` both assume `b8-role-shared` through IRSA. That role can `iam:PassRole`
`b8-admin` (AdministratorAccess). Two entry points, two 2-hop paths, one shared bottleneck.

## Expected tool output (legacy)
- 129 nodes, 46 edges
- 2 cross-layer escalation paths, risk score 5.5 each (confidence `potential`: a bare `iam:PassRole`)
- One remediation: remove `iam:PassRole` for `b8-admin` from `b8-role-shared`'s policy. One cut closes both
  paths, which is cheaper than removing two IRSA annotations (two cuts).

## Expected PMapper output
0 paths (no Kubernetes awareness).
