# BishopFox IAM-Vulnerable Evaluation

> **Note (superseded numbers).** The numbers in this file come from an earlier run
> (2026-07-03, `evaluation/bishopfox_result_SUPERSEDED.json`). The run used in the paper is
> `evaluation/benchmarks_raw/bishopfox_result.json`: 243 nodes, 1,338 edges and 1
> cross-layer path, produced in legacy mode with an author-added ServiceAccount bound
> to the starting role of the 3-hop AssumeRole scenario. In strict mode that path
> appears only if the starting role trusts an OIDC provider.

## Dataset
BishopFox iam-vulnerable (github.com/BishopFox/iam-vulnerable)
31 deliberate IAM privilege escalation scenarios deployed via Terraform.
265 IAM resources: 41 users, 45 roles, 3 groups.
Deployed against LocalStack 4.14.0 (free-resources modules only --
all 31 privesc-paths scenarios are IAM-only, no EC2/Lambda/etc needed).

## Our Tool Results
Graph: 215 nodes, 1337 edges.
Cross-layer escalation paths found: 0.
False positives: 0.

This is the CORRECT result. All 31 BishopFox scenarios are pure AWS
IAM -- no Kubernetes ServiceAccounts, no IRSA annotations. Our tool
correctly identifies that none of these configurations produce a
cross-layer escalation path, even in a dense 1337-edge graph.

## PMapper Results
Graph: 86 nodes (16 admins), 358 edges.
PMapper correctly found multiple IAM-only escalation paths including:
- UpdateAssumeRolePolicy (privesc14)
- CreateLoginProfile + target user is admin (privesc5)
- CreateAccessKey targeting admin user (privesc4)
- PassRole via Lambda (privesc15, privesc16)
- PassRole via CodeBuild
- PassRole via SageMaker (training job, processing job)
- SSM SendCommand / StartSession to EC2 with instance profile
- EC2 RunInstances with existing instance profile (privesc3)
- Several users already directly admin (privesc1, privesc7, etc.)

## Key Finding: Tools Are Complementary, Not Competing

This result reframes the comparison more precisely than a simple
"our tool vs PMapper" framing:

1. On PURE-IAM environments: PMapper correctly finds IAM escalation
   paths. Our tool correctly finds 0 CROSS-LAYER paths (they don't
   exist). Both tools produce correct results in their respective domains.

2. On CROSS-LAYER environments (Benchmarks 1-7): PMapper finds 0
   paths because it has no Kubernetes awareness. Our tool finds the
   complete attacker-reachable chain including the K8s entry point.

The gap is not that PMapper is wrong -- it is correct within its scope.
The gap is that PMapper's scope excludes the entire Kubernetes identity
layer, which means it cannot answer the question "who can actually
reach this IAM role chain from within the cluster?" Our tool answers
that question by modeling IRSA as a graph edge (C2) and unifying both
layers into one graph (C1).

This is a stronger and more defensible claim for the paper than
"our tool beats PMapper": the tools solve different (but adjacent)
problems, and ours extends the coverage to a class of attack path that
currently has no automated detection tooling.

## Methodological Note
The BishopFox dataset does not include any IRSA-annotated
ServiceAccounts or Kubernetes RBAC configurations, so it cannot
directly validate C2 (IRSA bridge edge) or C3 (cross-layer path
discovery). It validates: (a) our tool's false-positive rate on
pure-IAM environments is 0, and (b) scale handling on a denser
real-world-shaped graph (1337 edges vs our synthetic benchmarks).
