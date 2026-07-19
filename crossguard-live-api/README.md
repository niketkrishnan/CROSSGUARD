# CrossGuard Live — backend

On-demand scanning API for CrossGuard: point it at an AWS account (via
role assumption) + a Kubernetes cluster, and it runs your existing
ingestion → graph → pathfinder → risk → remediation pipeline and
returns results over HTTP, ready for a graph-visualization frontend.

## Status

Smoke-tested (auth, scan lifecycle, background task, error handling
all confirmed working). **Not yet wired to your actual CrossGuard core
modules** — that's a deliberate, isolated, one-file task. See below.

## 1. Wire up your core modules (required before this does anything real)

Open `app/core_adapter.py`. Every function in that file raises
`NotImplementedError` with a comment telling you exactly what to
import and call. This is the *only* file that needs to change to
connect this API to your existing `ingestion/`, `graph/`,
`pathfinder/`, `risk/`, `remediation/` modules — nothing else in this
repo references your core code directly.

## 2. Set up the IAM role your target accounts will trust

This app never accepts or stores raw AWS access keys — only an IAM
role ARN it assumes per-scan. In each AWS account you want to scan,
create a role with:

- **Trust policy**: allows `sts:AssumeRole` only from this app's own
  AWS identity (if deploying on EC2, that's the EC2 instance's IAM
  role/account; otherwise a dedicated IAM user's ARN), and require an
  `ExternalId` (a shared secret string you choose) to prevent a
  confused-deputy attack where someone tricks the app into assuming a
  role they don't own.
- **Permissions**: read-only IAM (`iam:List*`, `iam:Get*`) for
  scanning. If you want "apply fix" to work against that account too,
  add the specific write actions your remediation engine issues
  (e.g. `iam:UpdateAssumeRolePolicy`, `iam:DeleteRolePolicy`,
  `iam:RemoveUserFromGroup`) — nothing broader than that.

For local/demo use against LocalStack, `endpoint_url_override` on the
AWS target lets you point STS + IAM at `http://localhost:4566`
instead of real AWS.

## 3. Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `CROSSGUARD_API_KEY` | Yes | Shared API key clients must send as `X-API-Key`. Generate with `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`. Never commit this. |

## 4. Run locally

```bash
pip install -r requirements.txt
export CROSSGUARD_API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
uvicorn app.main:app --reload
```

Then visit `http://localhost:8000/docs` for interactive API docs
(FastAPI generates this automatically from the Pydantic models).

## 5. Deploy

**Docker (works anywhere — EC2, Render, Railway, Fly.io):**

```bash
docker build -t crossguard-live .
docker run -p 8000:8000 -e CROSSGUARD_API_KEY=<your-key> crossguard-live
```

**Render/Railway (simplest for a demo deployment):** connect this repo,
set `CROSSGUARD_API_KEY` in their environment variable settings, and
they'll build from the Dockerfile automatically. Both give you HTTPS
for free.

## API summary

| Endpoint | Purpose |
|---|---|
| `POST /scans` | Start a scan (returns immediately, `status=pending`) |
| `GET /scans/{id}` | Poll status |
| `GET /scans/{id}/graph` | Nodes + edges for the visualizer |
| `GET /scans/{id}/paths` | Vulnerable paths + risk scores + remediation |
| `POST /remediation/confirm` | Step 1 of applying a fix — returns a preview + single-use token |
| `POST /remediation/apply` | Step 2 — requires the token from `/confirm` |

All endpoints require the `X-API-Key` header.

## Design decisions worth knowing before you extend this

- **No raw AWS keys, ever** — only role ARNs + STS assumption. See
  `app/aws_auth.py`.
- **Apply is two calls, not one** — `/confirm` then `/apply`, so the
  frontend always shows an explicit preview before anything executes
  against real AWS. See `app/routers/remediation.py` docstring for why.
- **In-memory store** (`app/store.py`) — fine for a single-process demo
  deployment; swap for SQLite/Postgres before running multiple workers
  or expecting scans to survive a restart.
- **Single shared API key** — fine for you + your guides; upgrade to
  per-user auth if this gets more users. See `app/auth.py` docstring.

## Not yet built

- Frontend (graph visualization, credential input form, path list) —
  next piece.
- Re-scan-to-verify after applying a remediation (currently manual —
  trigger a new `POST /scans` against the same target).
