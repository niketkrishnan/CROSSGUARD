# Scale Test 1 -- Large IAM Config

## Purpose
Verify the tool handles a realistically-sized AWS account without
performance degradation or false positives at scale.

## Fixture sizes
- 50 IAM users (each with 1 inline policy)
- 100 IAM roles: 98 plain low-priv roles + 2 admin roles (AdministratorAccess)
- 10 IRSA-annotated ServiceAccounts: 2 pointing at the admin roles
  (genuine escalation), 8 pointing at random plain roles (no escalation,
  false-positive check at scale)

## Setup
1. ./benchmarks/reset_environment.sh
2. python3 benchmarks/scale_test_1/generate_aws_fixtures.py
3. ./benchmarks/scale_test_1/setup_k8s.sh
4. python3 benchmarks/scale_test_1/run_scale_test.py

## Results (5 runs, validated live against LocalStack + Minikube)

Resulting graph: 285 nodes, 250 edges.

| Metric | Mean | Std Dev |
|---|---|---|
| Wall-clock time | 6.16s | 0.574s |
| Peak memory | 11.7MB | 0.73MB |

Paths found: [2, 2, 2, 2, 2] across all 5 runs -- exactly matching
ground truth (scale-sa-0 and scale-sa-1 are the only 2 vulnerable
ServiceAccounts; the other 8 produced zero false positives across all
5 runs).

## Important finding during this test: admin-to-admin PassRole paths

The first version of this test found 4 paths, not 2. Both admin roles
have AdministratorAccess (Action:"*", Resource:"*"), which implicitly
grants iam:PassRole on every other role -- including each other. This
created two extra "paths" of the form
scale-sa-0 -> admin-role-A -> [PassRole] -> admin-role-B, which are
technically valid graph edges but not meaningful escalation findings:
once an attacker reaches ANY admin node, reaching a SECOND admin node
afterward represents no additional risk.

This led to a real fix in pathfinder/search.py
(_passes_through_earlier_admin): paths that pass through an admin node
before reaching their final (different) admin target are now excluded.
This is documented as a genuine design improvement discovered through
scale testing, not a pre-existing requirement -- exactly the kind of
finding scale testing at realistic size is meant to surface, which
would not have been caught by any of the 7 hand-built benchmarks (none
of which had two independently admin roles able to PassRole to each
other).

Regression-checked against Benchmark 6 (the existing multi-path case)
to confirm this fix does not affect genuinely distinct escalation
routes -- B6 still correctly reports 2 paths after the fix.
