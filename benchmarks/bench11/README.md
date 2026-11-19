# Benchmark 11 -- Adversarial and Evasion Cases

Wildcard principal, nested conditions, an obfuscated multi-hop chain and a circular trust.

## Setup
```bash
./benchmarks/reset_environment.sh
bash benchmarks/bench11/setup_aws.sh
# one ServiceAccount per role; the ServiceAccount name equals the role name
for sa in b11-circular-a b11-hop1 b11-nested-conditions b11-wildcard-principal-admin; do
  kubectl create serviceaccount "$sa" -n default
  kubectl annotate serviceaccount "$sa" -n default "eks.amazonaws.com/role-arn=arn:aws:iam::000000000000:role/$sa"
done
for m in legacy annotate strict; do
  echo "=== $m ==="; privesc-scan --endpoint-url http://localhost:4566 --semantics $m
done
```
This benchmark predates the IRSA trust check, so `strict` reports 0 paths partly because the setup has no OIDC trust.

## Expected tool output
- `legacy`: 3 paths
  - `b11-wildcard-principal-admin` (6.0, confirmed)
  - `b11-nested-conditions -> b11-nested-conditions-target` (5.5, potential)
  - `b11-hop1` -> `b11-hop2` -> `b11-hop3` -> `b11-hop4-admin`, 4 hops through PassRole, AssumeRole and PassRole (5.0, potential)
  - the circular-trust case (`b11-circular-a`) produces no path
- `annotate`: the same 3 paths, all `unresolved`
- `strict`: 0 paths

## Run and check (copy and paste)

Run from the repository root, in the project's virtual environment (`source venv/bin/activate`), with Docker and Minikube running. The first line loads `benchmarks/common.sh`, which sets the dummy AWS variables for LocalStack, defines the `cleanx` helper and checks the tools.

**Case:** Adversarial and evasion cases: a wildcard principal, nested conditions, an obfuscated multi-hop chain and a circular trust.

This benchmark predates the IRSA trust check: its setup gives the roles no valid OIDC trust, so it is run with `--semantics legacy`. Under the default `strict` mode the tool correctly drops those IRSA edges and reports 0 paths.

```bash
source benchmarks/common.sh
./benchmarks/reset_environment.sh && cleanx
bash benchmarks/bench11/setup_aws.sh 2>&1 | grep -E "complete|rror"
for sa in b11-circular-a b11-hop1 b11-nested-conditions b11-wildcard-principal-admin; do
  kubectl create serviceaccount "$sa" -n default
  kubectl annotate serviceaccount "$sa" -n default "eks.amazonaws.com/role-arn=arn:aws:iam::000000000000:role/$sa"
done
for m in legacy annotate strict; do echo "=== $m ==="; privesc-scan --endpoint-url http://localhost:4566 --semantics $m 2>&1 | grep -E "Found|No cross|^Path|-->" | grep -v WARNING; done
```

**Expected:** `legacy`: 3 paths (6.0, 5.5, 5.0). `annotate`: the same 3 paths, all unresolved. `strict`: 0 paths. The circular trust produces no path.
