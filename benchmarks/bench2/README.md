# Benchmark 2 -- Multi-hop IAM Chain After IRSA (3 hops)

## Setup
1. Reset environment: ./benchmarks/reset_environment.sh
2. Run ./benchmarks/bench2/setup_aws.sh
3. kubectl create serviceaccount bench2-sa -n default
4. kubectl annotate serviceaccount bench2-sa -n default eks.amazonaws.com/role-arn=arn:aws:iam::000000000000:role/b2-role-a
5. kubectl apply -f benchmarks/bench2/test-pod.yaml

## Analysis mode
This benchmark predates the IRSA trust check. Run the scan with `--semantics legacy`:
`privesc-scan --endpoint-url http://localhost:4566 --semantics legacy`.
Under the default `strict` mode the tool drops the IRSA edge (the setup gives `b2-role-a` an EC2 trust) and reports no path.

## Ground truth attack path

bench2-pod (Pod)
  -> runs as bench2-sa (ServiceAccount)
    -> IRSA bridge -> b2-role-a
      -> iam:PassRole -> b2-role-b
        -> sts:AssumeRole -> b2-admin-role (AdministratorAccess)

3 hops. Cross-layer: yes.

## Expected tool output
- 1 cross-layer escalation path found, risk score 5.0
- Remediation: remove the trust relationship allowing b2-role-b to assume b2-admin-role (or, equivalently, remove PassRole from b2-role-a, or remove the IRSA annotation -- any single edge in this chain is a valid minimum cut)

## Remediation validation (performed against real LocalStack)

Step: Before remediation -- Result: 1 path found (3 hops, risk score 5.0)
Step: Applied -- Result: Removed b2-role-b principal from b2-admin-role's trust policy
Step: After remediation -- Result: 0 paths found
Step: Edge count -- Result: 47 -> 46 (exactly 1 edge removed)

This confirms the remediation recommendation is not just a plausible-looking
string -- applying it actually breaks the attack path.

## Expected PMapper output
0 paths (PMapper has no Kubernetes awareness, cannot see this path at all)

## Run and check (copy and paste)

Run from the repository root, in the project's virtual environment (`source venv/bin/activate`), with Docker and Minikube running. The first line loads `benchmarks/common.sh`, which sets the dummy AWS variables for LocalStack, defines the `cleanx` helper and checks the tools.

**Case:** Multi-hop chain: ServiceAccount -> role-a, PassRole to role-b, AssumeRole into an admin role.

This benchmark predates the IRSA trust check: its setup gives the roles no valid OIDC trust, so it is run with `--semantics legacy`. Under the default `strict` mode the tool correctly drops those IRSA edges and reports 0 paths.

```bash
source benchmarks/common.sh
./benchmarks/reset_environment.sh && cleanx
./benchmarks/bench2/setup_aws.sh 2>&1 | grep -E "complete|rror"
kubectl create serviceaccount bench2-sa -n default
kubectl annotate serviceaccount bench2-sa -n default eks.amazonaws.com/role-arn=arn:aws:iam::000000000000:role/b2-role-a
kubectl apply -f benchmarks/bench2/test-pod.yaml
privesc-scan --endpoint-url http://localhost:4566 --semantics legacy 2>&1 | grep -vE "WARNING|^\[|^$"
```

**Expected:** 129 nodes, 47 edges, 1 path, 3 hops, risk 5.0. The cheapest fix is on the AssumeRole trust policy, not the annotation.
