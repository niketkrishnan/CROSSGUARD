# Benchmark 9 -- Realistic Near-Misses (2 exploitable, 2 safe)

Four configurations modelled on well-known EKS controllers.

## Setup
```bash
./benchmarks/reset_environment.sh
./benchmarks/bench9/setup_aws.sh
while read ns sa role; do
  kubectl create serviceaccount $sa -n $ns
  kubectl annotate serviceaccount $sa -n $ns eks.amazonaws.com/role-arn=arn:aws:iam::000000000000:role/$role
done <<'LIST'
kube-system b9-aws-node b9-aws-node-role
kube-system b9-cluster-autoscaler b9-cluster-autoscaler-role
kube-system b9-efs-csi-controller-sa b9-efs-csi-controller-role
default b9-amp-ingest b9-amp-ingest-role
LIST
privesc-scan --endpoint-url http://localhost:4566 --semantics legacy
```
Run with `--semantics legacy`: this benchmark predates the IRSA trust check.

## Expected tool output (legacy)
- 137 nodes, 56 edges
- 2 paths, both confidence `potential`:
  - 2 hops, risk 5.5: `b9-cluster-autoscaler -> b9-cluster-autoscaler-role --[iam:PassRole]--> b9-autoscaler-admin`
  - 3 hops, risk 5.0: `b9-aws-node -> b9-aws-node-role --[sts:AssumeRole]--> b9-shared-jump-role --[iam:PassRole]--> b9-autoscaler-admin`
- Not flagged, correctly: `b9-efs-csi-controller-sa` (PassRole scoped to a non-admin role) and `b9-amp-ingest` (no route to admin)
- Two remediations (the order can differ between runs): remove `iam:PassRole` for `b9-autoscaler-admin` from
  `b9-cluster-autoscaler-role` and from `b9-shared-jump-role`

## Running the benchmark

From the repository root, with the project's virtual environment active and Docker and Minikube running.

**Scenario:** Realistic near-misses: four cases modelled on well-known controllers, 2 exploitable (a PassRole to an admin role, and an AssumeRole then PassRole chain) and 2 safe (a scoped PassRole, and no route to admin).

This benchmark predates the IRSA trust check: its setup gives the roles no valid OIDC trust, so it is run with `--semantics legacy`. Under the default `strict` mode the tool correctly drops those IRSA edges and reports 0 paths.

```bash
source benchmarks/common.sh
./benchmarks/reset_environment.sh && cleanx
./benchmarks/bench9/setup_aws.sh 2>&1 | grep -E "complete|rror"
while read ns sa role; do
  kubectl create serviceaccount $sa -n $ns
  kubectl annotate serviceaccount $sa -n $ns eks.amazonaws.com/role-arn=arn:aws:iam::000000000000:role/$role
done <<'LIST'
kube-system b9-aws-node b9-aws-node-role
kube-system b9-cluster-autoscaler b9-cluster-autoscaler-role
kube-system b9-efs-csi-controller-sa b9-efs-csi-controller-role
default b9-amp-ingest b9-amp-ingest-role
LIST
privesc-scan --endpoint-url http://localhost:4566 --semantics legacy 2>&1 | grep -vE "WARNING|^\[|^$"
```

**Expected result:** 137 nodes, 56 edges, 2 paths (5.5 and 5.0), two fixes (the order can differ between runs). The two safe cases are not flagged.
