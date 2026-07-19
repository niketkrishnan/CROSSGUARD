# CrossGuard Live — backend

On-demand scanning API for CrossGuard: point it at an AWS account (via
role assumption) and a Kubernetes cluster, and it runs the core
ingestion → graph → pathfinder → risk → remediation pipeline and
returns results over HTTP for the graph-visualization frontend in
`../crossguard-live-frontend/`.

## Status

Fully wired to the core engine and tested end to end against LocalStack +
Minikube, covering all four benchmark scenarios below.

| Piece | Status |
|---|---|
| Scan pipeline (ingest → graph → paths → risk → remediation) | Working, verified against Benchmark 1 (1 path, 2 hops) and Benchmark 2 (1 path, 3 hops, risk 5.0) — exact match to documented ground truth |
| Remediation apply — `irsa_bridge` (Kubernetes) | Working, verified: applies the fix, re-scan confirms 0 paths |
| Remediation apply — `sts:AssumeRole` (AWS) | Working, verified on Benchmark 2 against real LocalStack IAM, including the empty-trust-policy edge case (see `core_adapter.py`) |
| Remediation apply — `group_membership` (AWS) | Implemented, unit-tested against a mock IAM client; not yet run against a live benchmark |
| Remediation apply — `iam:PassRole` (AWS) | Implemented for inline policies only, unit-tested against a mock IAM client; deliberately **refuses** (with an explanatory error) rather than editing an attached managed policy or narrowing a wildcard `Resource: "*"` grant, since either of those needs a human decision |
| Frontend | Built — see `../crossguard-live-frontend/index.html` |

`app/core_adapter.py` is the bridge between this API and the core engine
(`ingestion/`, `graph/`, `pathfinder/`, `scoring/`, `remediation/` at the
repo root) — it's a thin wrapper that imports and calls those modules
directly, with no duplicated analysis logic.

## 1. Set up the IAM role your target account will trust

This app never accepts or stores raw AWS access keys — only an IAM role
ARN it assumes per-scan. In each AWS account you want to scan, create a
role with:

- **Trust policy**: allow `sts:AssumeRole` only from this app's own AWS
  identity, and require an `ExternalId` (a shared secret string you
  choose) to prevent a confused-deputy attack.
- **Read permissions** (for scanning): `iam:List*`, `iam:Get*`.
- **Write permissions** (only if you want "Apply fix" to work against
  this account):
  - `iam:UpdateAssumeRolePolicy` — for `sts:AssumeRole` fixes
  - `iam:GetRolePolicy`, `iam:PutRolePolicy`, `iam:DeleteRolePolicy`,
    `iam:ListRolePolicies` — for `iam:PassRole` fixes on roles
  - `iam:GetUserPolicy`, `iam:PutUserPolicy`, `iam:DeleteUserPolicy`,
    `iam:ListUserPolicies` — for `iam:PassRole` fixes on users
  - `iam:RemoveUserFromGroup` — for `group_membership` fixes

For local/demo use against LocalStack, set `endpoint_url_override` on
the AWS target to `http://localhost:4566` to point STS + IAM there
instead of real AWS.

## 2. Kubeconfig permissions

For scanning: read access to ServiceAccounts, Roles, RoleBindings,
ClusterRoles, ClusterRoleBindings across the namespaces you want
analyzed. For "Apply fix" on an `irsa_bridge` finding: also `get` and
`update`/`patch` on ServiceAccounts (the fix removes one annotation).

Kubeconfigs are never persisted — used for one scan or one remediation
apply, then discarded. A K8s-side apply requires the kubeconfig to be
resubmitted with the `/remediation/apply` call, since it isn't kept
around from the scan (same reasoning as never storing AWS keys — see
`app/routers/remediation.py`).

## 3. Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `CROSSGUARD_API_KEY` | Yes | Shared API key clients must send as `X-API-Key`. Generate with `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`. Never commit this. |

## 4. Run locally

```bash
pip install -r requirements.txt
export PYTHONPATH=..:$PYTHONPATH   # so app can import ingestion/, graph/, etc. from the repo root
export CROSSGUARD_API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
uvicorn app.main:app --reload
```

Then either open `../crossguard-live-frontend/index.html` in a browser
(enter this API's URL + key under "API connection"), or visit
`http://localhost:8000/docs` for FastAPI's interactive API docs.

For LocalStack/Minikube testing, also export `AWS_ACCESS_KEY_ID=test`,
`AWS_SECRET_ACCESS_KEY=test`, `AWS_DEFAULT_REGION=us-east-1` before
starting uvicorn (boto3 needs *some* credentials configured to sign
requests, even fake ones).

## 5. Deploy

**Docker (works anywhere — EC2, Render, Railway, Fly.io):**

```bash
docker build -t crossguard-live .
docker run -p 8000:8000 -e CROSSGUARD_API_KEY=<your-key> crossguard-live
```

**Render/Railway (simplest for a demo deployment):** connect the repo,
set the root directory to `crossguard-live-api`, set `CROSSGUARD_API_KEY`
in their environment variable settings, and they'll build from the
`Dockerfile` automatically. Both give you HTTPS for free.

Before deploying publicly, restrict CORS in `app/main.py`
(`allow_origins=["*"]` is fine for local dev only — narrow it to your
actual deployed frontend's URL).

## API summary

| Endpoint | Purpose |
|---|---|
| `POST /scans` | Start a scan (returns immediately, `status=pending`) |
| `GET /scans` | List all scans |
| `GET /scans/{id}` | Poll status |
| `GET /scans/{id}/graph` | Nodes + edges for the visualizer |
| `GET /scans/{id}/paths` | Escalation paths + risk scores + remediation |
| `POST /remediation/confirm` | Step 1 of applying a fix — returns a human-readable preview and a single-use, short-lived token |
| `POST /remediation/apply` | Step 2 — requires the token from `/confirm`; requires `kubeconfig_yaml` too if the fix is K8s-side |

All endpoints require the `X-API-Key` header.

## Design decisions worth knowing before you extend this

- **No raw AWS keys, ever** — only role ARNs + STS assumption. See
  `app/aws_auth.py`.
- **Apply is two calls, not one** — `/confirm` then `/apply`, so the
  caller always sees an explicit preview before anything executes
  against real AWS/K8s. See `app/routers/remediation.py`.
- **Remediation only ever touches the exact edge identified** — one
  principal from one trust policy, one statement from one inline
  policy, one annotation from one ServiceAccount. It refuses rather
  than guesses when a fix would need to touch something broader (a
  managed policy, a wildcard grant). See `app/core_adapter.py`.
- **In-memory store** (`app/store.py`) — fine for a single-process demo
  deployment; swap for SQLite/Postgres before running multiple workers
  or expecting scans to survive a restart.
- **Single shared API key** — fine for a small number of trusted users;
  upgrade to per-user auth for a wider audience. See `app/auth.py`.

## Known limitations

- The Kubernetes client config is process-global (`kubernetes.config`'s
  usual behavior), so concurrent scans against *different* clusters in
  the same running instance aren't safe. Not an issue for single-user
  or demo use.
- `iam:PassRole` fixes on attached managed policies or wildcard
  `Resource: "*"` grants are not auto-applied — see the Status table
  above.
- No automatic re-scan-to-verify after applying a fix; trigger a new
  `POST /scans` against the same target to confirm a path closed.
