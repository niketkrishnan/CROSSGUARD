"""
gcp_probe.py -- generalizability probe (Section item 11).
Constructs a GCP Workload Identity Federation scenario directly as a
graph, using the exact same schema build_unified_graph produces for
AWS/K8s. Runs it through the REAL, installed pathfinder/search.py,
scoring/risk.py, and remediation/engine.py -- zero AWS-specific code
changes -- to test whether the core cross-layer escalation logic
generalizes to a different cloud's identity-federation model.

GCP Workload Identity Federation maps onto the same abstract pattern
as AWS IRSA:
  K8s ServiceAccount --(Workload Identity binding)--> GCP Service Account
  GCP Service Account --(iam.serviceAccounts.actAs / impersonation)--> GCP Service Account
  ... --> a Service Account with roles/owner (GCP's admin-equivalent)
"""
import sys
sys.path.insert(0, ".")
import networkx as nx
from pathfinder.search import find_all_cross_layer_paths, describe_path
from scoring.risk import score_all_paths
from remediation.engine import find_minimum_remediation

G = nx.DiGraph()

# K8s side (GKE)
G.add_node("k8s:sa:default:app-ksa", type="k8s_service_account", name="app-ksa", namespace="default", is_admin=False)

# GCP side
G.add_node("gcp:sa:app-gsa@project.iam.gserviceaccount.com", type="gcp_service_account", name="app-gsa", is_admin=False)
G.add_node("gcp:sa:deploy-gsa@project.iam.gserviceaccount.com", type="gcp_service_account", name="deploy-gsa", is_admin=True)  # has roles/owner

# Edge 1: Workload Identity binding (GCP's direct analog of AWS IRSA)
G.add_edge("k8s:sa:default:app-ksa", "gcp:sa:app-gsa@project.iam.gserviceaccount.com", type="workload_identity_bridge")

# Edge 2: service account impersonation (GCP's analog of AssumeRole/PassRole --
# app-gsa has roles/iam.serviceAccountTokenCreator on deploy-gsa)
G.add_edge("gcp:sa:app-gsa@project.iam.gserviceaccount.com", "gcp:sa:deploy-gsa@project.iam.gserviceaccount.com", type="iam.serviceAccountTokenCreator")

print("=== Running REAL, unmodified pathfinder/search.py against a GCP-modeled graph ===")
paths = find_all_cross_layer_paths(G)
print(f"Cross-layer paths found: {len(paths)}")
for p in paths:
    print(" ", describe_path(G, p))

print("\n=== Running REAL, unmodified scoring/risk.py ===")
scored = score_all_paths(G, paths)
for p in scored:
    print(f"  risk_score={p['risk_score']}  edge_types_seen_by_scorer={[G.edges[p['path'][i], p['path'][i+1]]['type'] for i in range(len(p['path'])-1)]}")

print("\n=== Running REAL, unmodified remediation/engine.py ===")
rem = find_minimum_remediation(G, scored)
for r in rem:
    print(" ", r["action"])

print("\n=== Verdict ===")
print(f"Cross-layer path detected: {len(paths) > 0}")
print("Zero AWS-specific code was modified to run this -- pathfinder/search.py")
print("operates purely on 'type' string prefixes ('k8s') and 'is_admin' flags,")
print("not on any AWS-specific literals.")
