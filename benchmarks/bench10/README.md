# Benchmark 10 -- False-Positive Stress Test (15 safe configurations)

All configurations are intended to be safe, so any path reported in `legacy` mode is a false positive
(explicit Deny, MFA-gated, conditioned PassRole and similar cases).

## Setup
```bash
./benchmarks/reset_environment.sh
bash benchmarks/bench10/setup_aws.sh
# one ServiceAccount per role; the ServiceAccount name equals the role name
for sa in b10-chain-start b10-cw-readonly b10-ddb-readonly b10-ec2-describe b10-explicit-deny-admin \
          b10-iam-readonly b10-logs-wildcard b10-mfa-gated-admin b10-minimal b10-passrole-conditioned \
          b10-passrole-scoped b10-s3-readonly b10-s3-scoped-star; do
  kubectl create serviceaccount "$sa" -n default
  kubectl annotate serviceaccount "$sa" -n default "eks.amazonaws.com/role-arn=arn:aws:iam::000000000000:role/$sa"
done
for m in legacy annotate strict; do
  echo "=== $m ==="; privesc-scan --endpoint-url http://localhost:4566 --semantics $m
done
```
This benchmark predates the IRSA trust check, so `strict` reports 0 paths partly because the setup has no OIDC trust.
Use `legacy` against `annotate` to see the policy-semantics effect.

## Expected tool output
- `legacy`: 4 paths (`b10-explicit-deny-admin` 6.0, `b10-mfa-gated-admin` 6.0, and two `b10-passrole-conditioned` paths at 5.5)
- `annotate`: 2 paths, confidence `unresolved` (`b10-mfa-gated-admin` and `b10-passrole-conditioned -> b10-mfa-gated-admin`);
  the explicit-Deny case is gone
- `strict`: 0 paths
