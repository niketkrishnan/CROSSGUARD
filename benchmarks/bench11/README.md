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
