# Benchmark 7 -- Cross-Namespace RBAC Resolution

## Scoping note
The brief's original framing ("Pod in namespace prod runs under SA in
namespace default") isn't valid Kubernetes -- a Pod's
spec.serviceAccountName always refers to an SA in the Pod's OWN
namespace, never a different one. The real, valid cross-namespace case
in Kubernetes RBAC is a RoleBinding living in namespace A whose
subject explicitly names a ServiceAccount from namespace B (via
subjects[].namespace). This benchmark tests that case, which directly
exercises the same namespace-resolution code path
(graph/builder.py:_add_rbac_binding_edges) that a real misconfigured
cluster could trigger.

## Setup
1. Reset environment: ./benchmarks/reset_environment.sh
2. kubectl create namespace bench7-ns
3. kubectl create serviceaccount bench7-sa -n default
4. kubectl apply -f benchmarks/bench7/cross-namespace-rbac.yaml

## Ground truth
A RoleBinding in bench7-ns binds bench7-role (also in bench7-ns) to a
ServiceAccount subject explicitly namespaced as default/bench7-sa --
i.e. the binding's namespace and the subject's namespace differ.

Expected: graph contains node k8s:sa:default:bench7-sa (NOT
k8s:sa:bench7-ns:bench7-sa) with an rbac_binding edge to
k8s:role:bench7-ns:bench7-role.

## Actual result (validated live against Minikube)
- G.has_node("k8s:sa:default:bench7-sa") -> True
- G.has_node("k8s:role:bench7-ns:bench7-role") -> True
- G.has_edge(sa_node, role_node) -> True, type=rbac_binding
- Confirms the SA was resolved to ITS OWN namespace (default), not the
  binding's namespace (bench7-ns) -- this is the specific bug this
  benchmark is designed to catch, and the code handled it correctly.

This is a low-privilege Role (pods get/list only), not an escalation
path -- it is a Module 2 (graph builder) completeness test, not a
cross-layer privilege escalation benchmark.

## Incidental finding
Running this after Benchmark 6 (without first deleting bench6-sa from
Minikube) surfaced a real, harmless warning from
graph/builder.py:_add_irsa_edges -- bench6-sa's IRSA annotation
referenced a b6-role-a ARN that no longer existed in the (reset)
LocalStack instance. The code logged a warning and skipped the stale
mapping rather than crashing, validating that defensive code path
against a genuine (if accidental) real-world scenario: stale IRSA
annotations left over after AWS-side roles are deleted/rotated.

## Running the benchmark

From the repository root, with the project's virtual environment active and Docker and Minikube running.

**Scenario:** Cross-namespace RBAC (Kubernetes only): a RoleBinding in another namespace names a ServiceAccount from `default`. Tests that the ServiceAccount resolves to its own namespace. No escalation path.

This benchmark predates the IRSA trust check: its setup gives the roles no valid OIDC trust, so it is run with `--semantics legacy`. Under the default `strict` mode the tool correctly drops those IRSA edges and reports 0 paths.

```bash
source benchmarks/common.sh
./benchmarks/reset_environment.sh && cleanx
kubectl create namespace bench7-ns
kubectl create serviceaccount bench7-sa -n default
kubectl apply -f benchmarks/bench7/cross-namespace-rbac.yaml
python3 - <<'EOF'
from ingestion.aws_ingestion import ingest_aws
from ingestion.k8s_ingestion import ingest_k8s, find_irsa_mappings
from graph.builder import build_unified_graph
aws = ingest_aws(endpoint_url="http://localhost:4566")
k8s = ingest_k8s()
G = build_unified_graph(aws, k8s, find_irsa_mappings(k8s["service_accounts"]))
sa, role = "k8s:sa:default:bench7-sa", "k8s:role:bench7-ns:bench7-role"
print("SA node:", G.has_node(sa), "| role node:", G.has_node(role))
print("edge:", G.has_edge(sa, role), "| type:", G.edges[sa, role]["type"] if G.has_edge(sa, role) else None)
print("wrong-namespace node absent:", not G.has_node("k8s:sa:bench7-ns:bench7-sa"))
EOF
```

**Expected result:** `SA node: True | role node: True`, `edge: True | type: rbac_binding`, `wrong-namespace node absent: True`.
