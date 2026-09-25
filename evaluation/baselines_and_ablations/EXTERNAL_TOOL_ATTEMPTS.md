# External tool attempts: IAM-Deescalate and IAMPERE

Both are cited in the paper's related-work table (Table I) as remediation-focused baselines. Neither is included as a running comparison in the original evaluation (only PMapper and Cloudsplaining were run). This records what was actually tried for each, honestly, rather than silently leaving them out a second time.

## IAM-Deescalate (Palo Alto Networks Unit 42)

**Attempted 2026-09-20.** Cloned successfully from `github.com/PaloAltoNetworks/IAM-Deescalate`. Dependencies are lightweight (`boto3 > 1.13`, `packaging`, `python-dateutil`) and install cleanly.

What it actually does: `audit` uses **PMapper** (the same baseline already in the paper) to build a full graph of a live AWS account, finds non-admin principals with a path to an admin principal, then `plan`/`apply` insert explicit-Deny inline policies to break those edges. It is not a standalone detector — it is PMapper's graph plus an automated remediation layer, and it inherits PMapper's blind spot (no Kubernetes/IRSA visibility), which the paper's Table I already states.

**Why it was not run to completion in this environment:** `audit` requires `principalmapper.graphing.graph_actions` to gather a live account graph via boto3 — either real AWS or, as the paper's own PMapper baseline (Section IV-C) already does, LocalStack. This sandbox has no LocalStack/Docker; the author's WSL environment does (it's what ran every other live verification in this document). The commands below are provided for the author to run there if a remediation-focused comparison is wanted; they were not executed by the author as of this writing, so no result is claimed.

```bash
# from a fresh directory, alongside the CrossGuard repo:
git clone https://github.com/nccgroup/PMapper.git
git clone https://github.com/PaloAltoNetworks/IAM-Deescalate.git
cp IAM-Deescalate/misc/gathering.py PMapper/principalmapper/graphing/gathering.py
cp IAM-Deescalate/misc/case_insensitive_dict.py PMapper/principalmapper/util/case_insensitive_dict.py
cd IAM-Deescalate && pip3 install -r requirements.txt
# point boto3 at LocalStack the same way the paper's PMapper baseline does
# (AWS_ENDPOINT_URL / --endpoint-url http://localhost:4566, env credentials),
# run one of the existing benchmarks/bench*/setup_aws.sh scripts, then:
python3 iam_deesc.py audit
```

Expected finding, based on the tool's own documented scope: on any B-series benchmark with an IRSA-mediated escalation (e.g. B1, B2, B6-far), `audit` should report **no** vulnerable principal, for the same structural reason PMapper itself misses these cases in Section IV-C (no Kubernetes-side visibility) — IAM-Deescalate cannot see an edge that never existed in PMapper's graph to begin with. This would not be a new finding beyond what Section IV-C already shows for PMapper directly; the value of actually running it would be confirming that the remediation layer doesn't somehow compensate for the underlying graph's blind spot, which is unlikely but unverified.

## IAMPERE (Hu et al., ASE 2023)

**Attempted 2026-09-20, search only — not cloned.** Source is public at `github.com/githubhuyang/iampere`. Its own repository layout makes clear this is a research prototype, not a runnable tool: it requires generating a PyTorch Geometric (PyG) training dataset, a pretrained GNN model (`data/pt_model`), and deploying a MaxSAT solver via its own `maxsat_env.sh`, before any repair can be attempted. There is no lightweight "point it at a policy and get an answer" entry point comparable to PMapper or IAM-Deescalate.

**Decision: not attempted further.** Standing up a GNN training/inference pipeline and a MaxSAT solver is a substantial side project disproportionate to what a baseline comparison needs here, and the paper's own Table I entry for IAMPERE ("MaxSAT + GNN repair... AWS IAM only") already accurately characterizes it as AWS-IAM-only with no Kubernetes visibility, which is the dimension this evaluation series is about. This is recorded as a deliberate scope decision, not a silent omission.
