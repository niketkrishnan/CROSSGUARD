"""
gcp_probe_v2.py -- same as gcp_probe.py, but demonstrates the fix for
the one hardcoded AWS-specific check found in v1: is_cross_layer()
checks for a literal "aws" type prefix. Patched here (monkeypatch,
not editing the actual repo file) to check "not k8s" instead --
a one-line, cloud-agnostic change -- to see if the REST of the
pipeline (BFS pathfinding, admin-exclusion patch, scoring, min-cut
remediation) works unmodified once that one check is broadened.
"""
import sys
sys.path.insert(0, ".")
import networkx as nx
import pathfinder.search as search_module

# The ONE change: broaden is_cross_layer from a hardcoded "aws" check
# to "any non-k8s node", i.e. cloud-agnostic.
def is_cross_layer_generic(G, path):
    has_k8s = any(str(G.nodes[n].get("type", "")).startswith("k8s") for n in path)
    has_other = any(not str(G.nodes[n].get("type", "")).startswith("k8s") for n in path)
    return has_k8s and has_other

search_module.is_cross_layer = is_cross_layer_generic

from pathfinder.search import find_all_cross_layer_paths, describe_path
from scoring.risk import score_all_paths
from remediation.engine import find_minimum_remediation

G = nx.DiGraph()
G.add_node("k8s:sa:default:app-ksa", type="k8s_service_account", name="app-ksa", namespace="default", is_admin=False)
G.add_node("gcp:sa:app-gsa@project.iam.gserviceaccount.com", type="gcp_service_account", name="app-gsa", is_admin=False)
G.add_node("gcp:sa:deploy-gsa@project.iam.gserviceaccount.com", type="gcp_service_account", name="deploy-gsa", is_admin=True)
G.add_edge("k8s:sa:default:app-ksa", "gcp:sa:app-gsa@project.iam.gserviceaccount.com", type="workload_identity_bridge")
G.add_edge("gcp:sa:app-gsa@project.iam.gserviceaccount.com", "gcp:sa:deploy-gsa@project.iam.gserviceaccount.com", type="iam.serviceAccountTokenCreator")

print("=== With the ONE-LINE is_cross_layer fix (hardcoded 'aws' -> 'not k8s') ===")
paths = find_all_cross_layer_paths(G)
print(f"Cross-layer paths found: {len(paths)}")
for p in paths:
    print(" ", describe_path(G, p))

scored = score_all_paths(G, paths)
for p in scored:
    print(f"  risk_score={p['risk_score']}")

rem = find_minimum_remediation(G, scored)
print("Remediation recommendations:")
for r in rem:
    print(" ", r["action"])
