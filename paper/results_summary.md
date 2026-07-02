# Evaluation Results Summary

## Table 1 -- Benchmark Correctness Results

| Benchmark | Description | Paths found | Ground truth | FP | FN | Remediation verified |
|---|---|---|---|---|---|---|
| B1 | Direct IRSA (1 hop) | 1 | 1 | 0 | 0 | Yes (1->0 paths) |
| B2 | Multi-hop chain (3 hops) | 1 | 1 | 0 | 0 | Yes (1->0 paths) |
| B3 | 5 SAs, 1 vulnerable | 1 | 1 | 0 | 0 | Yes (1->0 paths) |
| B4 | Group membership (same-layer) | N/A | N/A | 0 | 0 | N/A (completeness test) |
| B5 | No path (false positive control) | 0 | 0 | 0 | 0 | N/A (no path to remediate) |
| B6 | Multiple paths, ranking | 2 | 2 | 0* | 0 | Yes (2->0 paths, single fix) |
| B7 | Cross-namespace RBAC | N/A | N/A | 0 | 0 | N/A (completeness test) |

*B6 note: the 2-hop route via iam:PassRole-only (no paired use-action)
may be a false positive by the strict standard PMapper applies. Disclosed
as a known limitation. See evaluation/pmapper_comparison.md.

## Table 2 -- PMapper Comparison

| Benchmark | Our tool | PMapper | Note |
|---|---|---|---|
| B1 | 1 path (IRSA bridge, 1 hop) | 0 paths | PMapper has no K8s awareness |
| B2 | 1 complete path incl. K8s entry point | Partial: AWS-only sub-chain found, no entry point | PMapper sees the IAM sub-chain but cannot identify who can reach it |
| B3 | 1 path, 0 FP on 4 clean SAs | 0 paths | PMapper cannot see any of the 5 SAs |
| B4 | Edge found (same-layer parity) | Would find (same-layer AWS-only) | Parity case by design |
| B5 | 0 paths (correct analysis) | 0 paths (no visibility) | Same answer, different reason |
| B6 | 2 paths, correctly ranked | Partial: 1 of 2 routes (AssumeRole only, missed PassRole-only) | PMapper requires paired use-action for PassRole |
| B7 | Correct cross-namespace resolution | N/A | No RBAC concept in PMapper |

Core finding: PMapper correctly analyzes whatever is entirely within
AWS IAM, but cannot identify the actual attacker-reachable entry point
when that entry point is a compromised Kubernetes identity. Our tool
closes this gap via C1 (unified graph) and C2 (IRSA bridge edge).

## Table 3 -- Scale Test Results (5 runs each, mean +/- stdev)

| Test | Graph size | Time (mean) | Time (stdev) | Memory (mean) | Memory (stdev) | Correctness |
|---|---|---|---|---|---|---|
| Scale 1: 50 users, 100 roles, 10 IRSA SAs | 285 nodes, 250 edges | 6.16s | 0.574s | 11.7MB | 0.73MB | 2/2 paths found, 0 FP |
| Scale 2: 10-hop deep chain | 136 nodes, 61 edges | 1.04s | 0.052s | 10.6MB | 0.35MB | 10/10 hops, correct remediation |

Note: Scale Test 1 runtime is dominated by sequential boto3 API calls
during ingestion (Module 1), not by graph algorithm complexity. BFS
itself is effectively instantaneous even at 10 hops. Parallelizing
ingestion API calls is the highest-leverage optimization available if
runtime becomes a concern at larger account sizes.

## Table 4 -- Remediation Verification

| Benchmark | Paths before | Fix applied | Paths after | Edge delta | Verified |
|---|---|---|---|---|---|
| B1 | 1 | Remove IRSA annotation (vulnerable-sa) | 0 | 43->42 | Yes |
| B2 | 1 | Remove b2-role-b from b2-admin-role trust policy | 0 | 47->46 | Yes |
| B3 | 1 | Remove IRSA annotation (bench3-sa-2) | 0 | 43->42 | Yes |
| B6 | 2 | Remove IRSA annotation (bench6-sa) -- single fix, both paths | 0 | 52->51 | Yes |

Key result: in B6, one remediation action (recommended by the global
minimum-cut engine) broke two structurally different escalation routes
simultaneously. This directly validates the super-source/super-sink
min-cut design choice over per-path cuts.

## Table 5 -- Novel Contribution Coverage

| Contribution | Test(s) that validate it |
|---|---|
| C1: Unified cross-layer graph | B1-B7 (all benchmarks use the unified graph) |
| C2: IRSA modeled as graph edge | B1, B2, B3, B5, B6, Scale 1, Scale 2 |
| C3: Cross-layer path discovery | B1, B2, B3, B6, Scale 1, Scale 2 + PMapper comparison |
| C4: Minimal remediation | B1, B2, B3, B6 (remediation verification table) |

## Known Limitations (for paper limitations section)

1. iam:PassRole edges are created for any PassRole grant, regardless
   of whether a paired use-action exists. This may produce false
   positives on PassRole-only grants. Mitigation: flag as a
   conservative design choice (recall over precision) and list
   paired-action checking as future work.

2. is_admin detection checks AdministratorAccess ARN and Action:"*"/
   Resource:"*" inline policies. Does not account for SCPs,
   permission boundaries, or session policies that might restrict
   effective admin access. These are noted as out-of-scope in the
   threat model.

3. Attached managed policy resolution requires iam:GetPolicy and
   iam:GetPolicyVersion. Without these, affected policies are skipped
   with a warning rather than failing the scan.

4. IRSA detection is annotation-based, not OIDC-validation-based.
   A stale annotation pointing at a deleted role produces a warning
   and a gracefully skipped edge, not a false positive path (validated
   incidentally during Benchmark 7 testing).

5. Runtime is dominated by sequential boto3 ingestion API calls. At
   very large account sizes (thousands of roles) this may become slow.
   Parallelization is the recommended future optimization.
