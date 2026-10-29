# Evaluation Results Summary

**This file is a short pointer/snapshot, not the source of truth.** The
complete, current evaluation record — with a full change-log of every
correction made across evaluation sessions — is
`evaluation_complete_final.md` at the repo root. Read that file for
anything beyond the headline numbers below; this file exists only so a
reader browsing `paper/` doesn't hit a dead end.

*(An earlier version of this file, covering only benchmarks B1-B7 and
predating the real-world evaluation, the scalability sweep, and the
PassRole Confirmed/Conservative-Potential classification, has been
replaced — it was going stale independently of the main evaluation
record. See `evaluation_complete_final.md` Section 0 for the full
change history.)*

## Headline numbers (see `evaluation_complete_final.md` for full detail + sources)

- **Synthetic benchmark confusion matrix (B1-B9)**: TP=9, FP=0, FN=0,
  TN=5 -> Precision = Recall = F1 = 1.000
- **Real-world live-verified**: 44/44 correct, 0 FP, 0 FN, across 6
  independent mechanical extraction methods on real EKS repositories
  (full per-case table: `evaluation/real_world/RW_MANIFEST.md`)
- **Scalability**: empirical exponent about 2.01 (R^2 > 0.98), up to 25,000
  nodes (`evaluation/scalability/`)
- **Remediation**: 40/40 trials successful across 4 fix types, 0 side
  effects (`evaluation/remediation_trials/`)
- **PassRole two-tier classification**: of 12 tested PassRole-relevant
  paths, 5 Confirmed (every hop backed by explicit `sts:AssumeRole`
  trust), 7 Conservative-Potential (relies on a bare `iam:PassRole`
  grant with no independently-modeled completing action) --
  `evaluation/passrole_classification/`
- **B10 FP stress test**: 14/14 standard safe configs correctly
  unflagged; 2 deliberately adversarial edge cases (explicit Deny,
  MFA-gated trust) exposed one documented, root-caused limitation:
  CrossGuard checks for presence of a trust/policy relationship, not
  policy Conditions
- **B11 adversarial/evasion testing**: 4/4 structurally correct,
  including cycle-safety. The wildcard-trust case's detection is via
  IRSA binding only -- `graph/builder.py` explicitly does not evaluate
  wildcard (`Principal: {"AWS": "*"}`) trust as a graph edge. Do not
  cite this case as evidence of wildcard-trust modeling.
- **Baselines**: PMapper (`principalmapper` v1.1.5) correctly traces
  AWS-side `sts:AssumeRole` chains but cannot see the K8s-to-AWS
  bridge at all; Cloudsplaining (v0.9.1) misses the same benchmarks for
  two independent structural reasons (default `AdministratorAccess`
  exclusion, single-policy pattern matching instead of cross-role graph
  traversal)

## Known Limitations (for paper limitations section)

1. Policy Condition evaluation (explicit Deny, MFA/context requirements)
   is not modeled -- root-caused and documented via B10.
2. Wildcard trust principals (`Principal: {"AWS": "*"}`) are not
   evaluated as a graph edge -- confirmed directly in `graph/builder.py`.
3. Bare `iam:PassRole` grants with no independently-modeled completing
   action are reported as Conservative-Potential, not a confirmed
   exploit chain -- see `evaluation/passrole_classification/`.
4. `is_admin` detection checks the `AdministratorAccess` managed policy
   and `Action:"*"`/`Resource:"*"` inline/attached policies; does not
   account for SCPs, permission boundaries, or session policies.
5. Attached managed policy resolution requires `iam:GetPolicy` and
   `iam:GetPolicyVersion`; without them, affected policies are skipped
   with a warning rather than failing the scan.
6. IRSA detection is annotation-based, not OIDC-validation-based -- a
   stale annotation pointing at a deleted role produces a warning and a
   gracefully skipped edge, not a false positive path.
7. Runtime is dominated by sequential boto3 ingestion API calls at very
   large account sizes; parallelization is the recommended future
   optimization. Pathfinding itself is O(n^2) from entry-point x
   admin-node pair checking; a multi-source BFS would reduce this
   toward O(n*m) (future work, not yet implemented).
