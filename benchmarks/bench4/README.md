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

## Run and check (copy and paste)

Run from the repository root, in the project's virtual environment (`source venv/bin/activate`), with Docker and Minikube running. The first line loads `benchmarks/common.sh`, which sets the dummy AWS variables for LocalStack, defines the `cleanx` helper and checks the tools.

**Case:** Same-layer group escalation (AWS only): a low-privilege user is a member of an admin group. Not cross-layer, so the main scan reports no path.

This benchmark predates the IRSA trust check: its setup gives the roles no valid OIDC trust, so it is run with `--semantics legacy`. Under the default `strict` mode the tool correctly drops those IRSA edges and reports 0 paths.

```bash
source benchmarks/common.sh
./benchmarks/reset_environment.sh && cleanx
./benchmarks/bench4/setup_aws.sh 2>&1 | grep -E "complete|rror"
python3 - <<'EOF'
from ingestion.aws_ingestion import ingest_aws
from ingestion.k8s_ingestion import ingest_k8s, find_irsa_mappings
from graph.builder import build_unified_graph
from pathfinder import search as ps
aws = ingest_aws(endpoint_url="http://localhost:4566")
k8s = ingest_k8s()
G = build_unified_graph(aws, k8s, find_irsa_mappings(k8s["service_accounts"]))
user  = "arn:aws:iam::000000000000:user/b4-low-priv-user"
group = "arn:aws:iam::000000000000:group/b4-admin-group"
print("edge exists:", G.has_edge(user, group), "| type:", G.edges[user, group]["type"] if G.has_edge(user, group) else None)
admins = ps.find_admin_nodes(G)
print("group is an admin sink:", group in admins)
for p in ps.find_escalation_paths(G, user, admins):
    print(p["hops"], "hop(s) | cross_layer:", p["cross_layer"], "|", ps.describe_path(G, p))
print("paths reported by the main scan (cross-layer only):", len(ps.find_all_cross_layer_paths(G)))
EOF
```

**Expected:** `edge exists: True | type: group_membership`, `group is an admin sink: True`, `1 hop(s) | cross_layer: False`, and `0` paths from the main scan.
