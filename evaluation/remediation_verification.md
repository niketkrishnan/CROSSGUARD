# Remediation Verification Results

For each benchmark with a found path: run tool, apply the exact
remediation command/action the tool output, re-run tool, confirm 0
paths remain. This proves remediation actually works -- not just that
it prints a plausible-looking string.

| Benchmark | Paths before | Remediation applied | Paths after | Edges before -> after | Verified |
|---|---|---|---|---|---|
| B1 | 1 | Remove IRSA annotation from vulnerable-sa | 0 | 43 -> 42 | Yes |
| B2 | 1 | Remove b2-role-b from b2-admin-role trust policy | 0 | 47 -> 46 | Yes |
| B3 | 1 | Remove IRSA annotation from bench3-sa-2 | 0 | 43 -> 42 | Yes |
| B4 | N/A | N/A (same-layer completeness test, not an escalation finding) | N/A | N/A | N/A |
| B5 | 0 | N/A (false-positive control -- no path exists to remediate) | 0 | N/A | N/A |
| B6 | 2 | Remove IRSA annotation from bench6-sa (single fix breaks BOTH paths) | 0 | 52 -> 51 | Yes |
| B7 | N/A | N/A (RBAC completeness test, not an escalation finding) | N/A | N/A | N/A |

## Key finding: global minimum cut correctly identifies shared bottlenecks

B6 is the most important row in this table. Two structurally different
escalation routes (one via iam:PassRole, one via iam:PassRole +
sts:AssumeRole) both originate from the same IRSA-bridged role. The
remediation engine's global min-cut (graph/builder.py super-source/
super-sink reduction, see Module 5 implementation notes) correctly
identified that cutting the single shared IRSA edge breaks both paths
simultaneously, rather than recommending two separate fixes. This
directly validates the per-path-cut deduplication bug found and fixed
during Module 5 development (see commit history) was a real, impactful
fix and not just a unit-test nicety.
