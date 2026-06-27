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
