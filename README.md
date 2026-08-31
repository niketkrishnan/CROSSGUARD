# Unified Cross-Layer Privilege Escalation Analysis and Remediation Framework

A research tool that unifies AWS IAM and Kubernetes RBAC into a single
directed graph, discovers privilege-escalation paths that cross from
Kubernetes into AWS (via IRSA), and computes the minimum permission
change needed to break each path.

## Why this exists

Existing IAM privilege-escalation tools (PMapper, TAC, CloudLens,
SkyEye, Cloudsplaining, Pacu) only analyze AWS IAM. None of them read
Kubernetes RBAC, and none of them model IRSA (IAM Roles for Service
Accounts) as a graph edge. This means a real, exploitable attack path
like:

Pod -> ServiceAccount (IRSA-annotated) -> AWS IAM Role -> AdministratorAccess

is invisible to every one of them. This tool finds it.

## Novel contributions

1. **Unified cross-layer graph** -- Kubernetes RBAC and AWS IAM entities in one `networkx.DiGraph`.
2. **IRSA modeled as a graph edge** -- the `eks.amazonaws.com/role-arn` annotation becomes a directed edge from a K8s ServiceAccount to an AWS IAM role.
3. **Cross-layer path discovery** -- BFS traversal finds escalation paths that start in Kubernetes and end at AWS admin.
4. **Minimal remediation** -- a global minimum edge cut (via super-source/super-sink reduction) computes the smallest set of permission changes that breaks every found path simultaneously.

## Installation

```bash
git clone <your-repo-url>
cd iam-k8s-privesc
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

This installs the `privesc-scan` command.

## Usage

Against real AWS + a real/in-context Kubernetes cluster:

```bash
privesc-scan --aws-profile my-profile
```

Against LocalStack (local fake AWS) + Minikube, for testing:

```bash
privesc-scan --endpoint-url http://localhost:4566
```

Write the full structured result to JSON as well:

```bash
privesc-scan --endpoint-url http://localhost:4566 --output-json result.json
```

All options:

```bash
privesc-scan --help
```

## Architecture

| Module | File | Responsibility |
|---|---|---|
| Ingestion | `ingestion/aws_ingestion.py`, `ingestion/k8s_ingestion.py` | Pull AWS IAM + K8s RBAC data, detect IRSA bridge mappings |
| Graph Builder | `graph/builder.py` | Build the unified cross-layer `DiGraph` |
| Pathfinder | `pathfinder/search.py` | BFS search for cross-layer escalation paths |
| Risk Scorer | `scoring/risk.py` | Rank found paths by severity |
| Remediation | `remediation/engine.py` | Global minimum-cut remediation recommendations |

## Running the test suite

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

55 tests, covering policy parsing, ingestion (against mocked AWS/K8s
clients), graph construction, pathfinding, risk scoring, and
remediation (including a global-minimum-cut correctness test that
caught a real per-path-cut deduplication bug during development).

## Reproducing the benchmarks locally

Requires Docker (for LocalStack) and Minikube (for a local Kubernetes
cluster).

```bash
# 1. Start LocalStack (local fake AWS, no account/token needed)
docker run -d --name localstack -p 4566:4566 localstack/localstack:4.14.0

# 2. Start Minikube (local real Kubernetes cluster)
minikube start --driver=docker

# 3. Set AWS env vars to point at LocalStack
export AWS_DEFAULT_REGION=us-east-1
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test

# 4. Set up Benchmark 1
./benchmarks/bench1/setup_aws.sh
kubectl create serviceaccount vulnerable-sa -n default
kubectl annotate serviceaccount vulnerable-sa -n default \
  eks.amazonaws.com/role-arn=arn:aws:iam::000000000000:role/admin-role
kubectl apply -f benchmarks/bench1/test-pod.yaml

# 5. Run the tool
privesc-scan --endpoint-url http://localhost:4566
```

Expected output: 1 cross-layer escalation path
(`vulnerable-sa --[irsa_bridge]--> admin-role`, risk score 6.0), with a
remediation recommendation to remove the IRSA annotation.

See `benchmarks/bench1/README.md` for the documented ground truth.

**Note:** LocalStack does not persist IAM resources across container
restarts. If you stop/restart the container, rerun
`./benchmarks/bench1/setup_aws.sh` before scanning again.

## Web interface (CrossGuard Live)

The CLI above is the core tool. There is also a web application built on
top of the same engine -- a FastAPI backend that wraps `ingest_aws`,
`ingest_k8s`, `build_unified_graph`, `find_all_cross_layer_paths`,
`score_all_paths`, and `find_minimum_remediation` behind an HTTP API, and
a single-file browser frontend that visualizes the graph and lets you
apply a remediation with one click.

```
crossguard-live-api/       FastAPI backend -- scan orchestration + REST API
crossguard-live-frontend/  Single-file HTML/JS graph visualizer
```

The web app does not duplicate any analysis logic -- `crossguard-live-api/app/core_adapter.py`
is a thin bridge that imports and calls the exact same functions used by
`main.py` above. Same engine, same benchmarks apply, same results.

**Quick start:**

```bash
cd crossguard-live-api
pip install -r requirements.txt
export PYTHONPATH=..:$PYTHONPATH
export CROSSGUARD_API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
uvicorn app.main:app --reload
```

Then open `crossguard-live-frontend/index.html` in a browser, enter the
API URL + key, and run a scan. See `crossguard-live-api/README.md` for
full setup (including the IAM trust policy needed to let it assume a
role) and deployment instructions.

**Security model:** no raw AWS credentials or kubeconfigs are ever
stored -- only `sts:AssumeRole` against a role you configure, held in
memory for one scan/apply and discarded. Applying a remediation is a
two-step confirm-then-apply flow with a single-use token. Full details
in `crossguard-live-api/README.md`.

## Comparison with existing tools

Running PMapper against the same benchmark environment finds 0
cross-layer paths, because PMapper has no Kubernetes awareness at all
-- it never reads RBAC, never sees the IRSA annotation, and therefore
cannot represent this attack path in any form.

## Evaluation & Results

Full evaluation record, evidence trail, and reproducibility details live
in `evaluation_complete_final.md` (repo root) and the `evaluation/`
directory (`evaluation/README.md` is the index). Highlights:

- Confusion matrix: TP=9, FP=0, FN=0, TN=5 on 9 synthetic benchmarks
- Real-world: 44/44 correct, 0 FP, 0 FN, across 6 independent extraction
  methods on real EKS repositories (`evaluation/real_world/RW_MANIFEST.md`
  for the full per-case table)
- Scalability: empirically O(n^2.012), R^2=0.9852, up to 25,000 nodes
- PMapper and Cloudsplaining baseline comparisons, plus documented,
  root-caused limitations (policy Condition evaluation, wildcard trust)

## Limitations

- `is_admin_role` detection currently checks the `AdministratorAccess`
  managed policy and inline/attached policies with `Action: "*"` /
  `Resource: "*"`; it does not yet account for SCPs, permission
  boundaries, or session policies.
- Attached managed policy resolution requires `iam:GetPolicy` and
  `iam:GetPolicyVersion` permissions on the credentials used to run the
  scan; without them, those policies are silently skipped (logged as a
  warning) rather than failing the whole scan.
- IRSA detection is annotation-based (reads `eks.amazonaws.com/role-arn`)
  and does not verify the OIDC trust relationship is actually correctly
  configured on the AWS side -- a path is reported if the annotation
  exists and the referenced role exists in the ingested AWS data, even
  if the OIDC federation itself would currently fail.

## Running via Docker (no local Python setup required)

```bash
docker build -t privesc-scan .

# Requires --network host (Linux/WSL2 Docker) so the container can reach
# LocalStack and Minikube on 127.0.0.1 exactly as the host sees them.
# Mount ~/.kube and ~/.minikube read-only since Minikube's kubeconfig
# references certificate files by absolute host path.
docker run --rm --network host \
  -v ~/.kube:/root/.kube:ro \
  -v ~/.minikube:/home/zoro/.minikube:ro \
  privesc-scan --endpoint-url http://localhost:4566
```

Note: `--network host` is Linux-only (works under WSL2). On Docker
Desktop for Mac, you would need `host.docker.internal` for the AWS side
and a different strategy for reaching Minikube (e.g. running the
container inside the Minikube VM's Docker daemon via
`eval $(minikube docker-env)`), which hasn't been tested here.
