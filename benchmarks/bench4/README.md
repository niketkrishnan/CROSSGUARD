# Benchmark 4 -- Group Membership Escalation (Same-Layer Completeness Test)

## Important scoping note
This benchmark is intentionally SAME-LAYER (AWS IAM only), not
cross-layer. AWS IAM groups can only contain Users, never Roles, and
IRSA (AssumeRoleWithWebIdentity) always lands an identity in a Role's
session, never a User's. There is therefore no way to construct a real,
valid IRSA -> ... -> Group chain on actual AWS -- doing so would test
something that cannot happen in practice. This benchmark instead
validates Completeness Test C-series: that the group_membership edge
type is correctly modeled and correctly traversed by the pathfinder,
which is a necessary building block even though it never appears
combined with an irsa_bridge edge in the same path.

## Setup
1. Reset environment: ./benchmarks/reset_environment.sh
2. Run ./benchmarks/bench4/setup_aws.sh

## Ground truth

b4-low-priv-user
  -> group_membership -> b4-admin-group (AdministratorAccess attached)

1 hop. Cross-layer: false (correctly classified -- no K8s entities involved).

## Actual result (validated live against LocalStack)
- G.has_edge(user_arn, group_arn) -> True, type=group_membership
- find_admin_nodes(G) correctly identifies the GROUP itself as an admin
  node (not just roles) -- validates is_admin_role works correctly
  when AdministratorAccess is attached directly to a group
- find_escalation_paths() finds the 1-hop path, cross_layer=False (correct)

Note: this path is NOT surfaced by find_all_cross_layer_paths() / the
main privesc-scan CLI output, since that function only reports paths
flagged cross_layer=True. This is correct, intentional behavior --
same-layer admin-via-group-membership is a known, well-covered case for
existing single-layer tools (PMapper etc.); it is not part of this
tool's novel contribution and is included here purely as a unit-level
completeness check on Module 2.

## Expected PMapper output
PMapper WOULD find this path (it's pure AWS IAM, no K8s involved) --
this is one of the few cases where existing tools have parity with ours.
