# Policy-Semantics Evaluation: Deny, Condition, IRSA-Trust, Wildcard-Trust and PassRole-Pairing Analysis

This document is part of the main evaluation record for CrossGuard. It describes what was added to the analyzer, why, how it was verified, what the verification showed, and exactly which statements in the paper it changes. It is written to be read cold by whoever continues the paper. Everything marked **live** was run by the author on LocalStack 4.14.0 and Minikube (WSL, Ubuntu) on 2026-09-19. Everything marked **offline** was run on in-memory fixtures without LocalStack.

Code: `ingestion/policy_eval.py`, `graph/builder.py`, `pathfinder/search.py`, `remediation/engine.py`, `main.py`. Evidence: `evaluation/policy_semantics/` (including `differential/`). Pre-change commit: `dc77ca1`.

## 1. Why this was done

The original evaluation reported P = R = F1 = 1.000 on 9 benchmarks and 44/44 on extracted configurations. Those labels were written by the tool's authors, and the analyzer only checked that a trust or permission relationship *exists*. Three documented limitations followed from that: L1 (any `iam:PassRole` grant creates an edge), L4 (explicit Deny and Condition blocks ignored, producing the 3 false-positive cases in B10) and L7 (wildcard trust principals skipped, so the B11 wildcard "true positive" came from IRSA reachability only). The goal was to fix those limitations in the tool itself, re-measure, and find out what else a stricter reading of AWS semantics exposes.

## 2. What was implemented

| Area | Original behaviour | New behaviour |
|---|---|---|
| Explicit Deny (L4) | Ignored | Applied per action and resource on every edge the model creates (PassRole, AssumeRole) and on the admin sink. A Deny covering all actions and resources makes the role `inert` (not an admin sink). A Deny covering everything whose Condition is undecidable makes the sink `unresolved`. Other Denies are recorded on the node (`admin_partial_denies`) and do **not** downgrade admin status. |
| Conditions (L4) | Ignored | Three-valued evaluation (true / false / unknown). Supported operators: `StringEquals`, `StringNotEquals`, `StringEqualsIgnoreCase`, `StringNotEqualsIgnoreCase`, `StringLike`, `StringNotLike`, `ArnEquals`, `ArnLike`, `ArnNotEquals`, `ArnNotLike`, `Bool`, `Null`, and `...IfExists` variants. Numeric, IP, date, `ForAnyValue`/`ForAllValues` and policy variables (`${...}`) evaluate to unknown. Unknown never becomes true or false: the edge is kept and labelled `unresolved`. |
| IRSA trust (new) | The edge was created from the annotation alone; the role's trust policy was never read | The role's trust policy must contain an Allow for `sts:AssumeRoleWithWebIdentity` to an OIDC federated principal whose conditions hold for the ServiceAccount: `sub` = `system:serviceaccount:<namespace>:<name>`, `aud` = `sts.amazonaws.com`, and no MFA context. Result recorded on the edge as `trust_status` (valid / invalid / unresolved / not_evaluated). Optional `--oidc-provider-arn` requires the role to trust exactly that provider; otherwise any OIDC-provider principal is accepted because the cluster issuer is unknown offline. |
| PassRole pairing (L1) | Any grant = edge; only a literal ARN or `"*"` was understood | Evaluated per target role, so Resource globs (e.g. `arn:...:role/app-*`) work. The `iam:PassedToService` condition is checked against the services the target role actually trusts, and the target's trust conditions (e.g. MFA) are checked for service assumption. An edge is `confirmed` only if the caller also holds a paired completing action for a usable service (catalog in `PAIRED_ACTION_CATALOG`); otherwise `potential`. |
| Wildcard trust (L7) | `Principal:"*"` skipped | Recorded on the role node, listed in `wildcard_trust_roles` as an exposure finding, and turned into AssumeRole edges from every identity whose own policy allows `sts:AssumeRole` on that role. Conditioned wildcard trust (e.g. `aws:PrincipalOrgID`) is `unresolved`. |
| Parallel mechanisms | One edge per node pair; a later type overwrote an earlier one (PassRole over AssumeRole) | Every mechanism is kept in `edge_types` with its own confidence; edge confidence is the best of its mechanisms; the legacy `type` field is unchanged so risk scoring is unchanged. Remediation emits one fix per mechanism, because severing the pair requires removing all of them. |
| Path output | No confidence information | Each path carries `confidence` (weakest edge or sink), `weakest_edge`, `irsa_trust`, `sink_admin_status`. Computed by `annotate_path_confidence`, a separate function, so the timed path-discovery code is untouched. |
| Audit trail | None | Every edge the evaluator removes is logged with its reason in `suppressed_edges`. |
| CLI | None | `--semantics strict|annotate|legacy` (default `strict`), `--oidc-provider-arn`. |

**Confidence tiers.** `confirmed`: every edge confirmed and the sink is full admin. `potential`: at least one hop is a bare PassRole grant. `unresolved`: at least one edge or sink depends on context not known statically (undecidable Condition, invalid or unknown IRSA trust, conditional Deny).

**Modes.**
- `legacy`: original presence-only behaviour, kept for before/after comparison.
- `annotate`: all checks run; every edge is kept and labelled. Shows what `strict` would remove.
- `strict` (default): edges that are definitely unusable under the analyzed abstraction are dropped and logged: invalid IRSA trust, a PassRole target no service can assume, an explicit Deny.

**Paired-action catalog.** Services and the action sets that make a bare PassRole exploitable: Lambda (CreateFunction + InvokeFunction, or CreateFunction + CreateEventSourceMapping, or UpdateFunctionConfiguration + InvokeFunction), EC2 (RunInstances), CloudFormation (CreateStack), Glue (CreateDevEndpoint or UpdateDevEndpoint), SageMaker (CreateNotebookInstance, CreateProcessingJob or CreateTrainingJob), ECS tasks (RegisterTaskDefinition + RunTask), CodeBuild (CreateProject + StartBuild), Data Pipeline (CreatePipeline + PutPipelineDefinition + ActivatePipeline). The catalog was assembled from published technique lists (Rhino Security Labs, cited as [21], and PMapper's catalog). **Each entry still has to be checked against those sources before the catalog is described as complete in the paper.**

## 3. Evaluation method

1. **Legacy fidelity check (live).** B10 and B11 were re-created in LocalStack with the existing setup scripts, and the analyzer was run with `--semantics legacy`. The result had to equal the earlier raw results and the paper (B10: 4 flagged paths in 3 cases; B11: 3 paths). This shows the modified code reproduces the original behaviour exactly, so before/after differences are attributable to the new checks.
2. **New semantics on the same live environments.** The same environments were analyzed with `annotate` and `strict`.
3. **Offline replay with two fixture variants.** The B10 and B11 scripts were transcribed into Python (`replay.py`) and fed straight to the builder, plus 8 regression fixtures written for the new mechanisms. Each case runs in all three modes.
   - *as-built*: original trust policies. Every IRSA-bound role trusts `ec2.amazonaws.com`.
   - *irsa-realistic*: trust of ServiceAccount-bound roles rewritten to a proper OIDC trust with matching `sub`/`aud` (an MFA condition is carried over where the original had one). Everything else is unchanged. This isolates the Deny, Condition and PassRole logic from the trust-policy problem in Finding 1.
4. **Differential test of the policy evaluator against PMapper's independent matcher** (section 4.3), run with a fixed seed and a positive control.
5. **Unit tests.** 98 tests pass (56 original, 42 new).

Truth labels in the replay are the author's reading of AWS semantics, not an independent oracle. They are used only to show which mechanism removes which false positive. The 8 regression fixtures exercise the code paths that were written for them and are **not** evidence of accuracy.

## 4. Results

### 4.1 Live results (LocalStack 4.14.0, Minikube, 2026-09-19)

Legacy fidelity check: **passed**. Legacy mode found 4 paths for B10 and 3 for B11, matching `benchmark10_result_v2.json`, `benchmark11_result.json` and the paper.

| Benchmark | Mode | Paths | Confirmed / potential / unresolved | Exposure findings | Suppressed edges |
|---|---|---|---|---|---|
| B10 | legacy | 4 | 2 / 2 / 0 | 0 | 0 |
| B10 | annotate | 2 | 0 / 0 / 2 | 0 | 15 |
| B10 | strict | 0 | 0 / 0 / 0 | 0 | 29 |
| B11 | legacy | 3 | 1 / 2 / 0 | 0 | 0 |
| B11 | annotate | 3 | 0 / 0 / 3 | 1 | 0 |
| B11 | strict | 0 | 0 / 0 / 0 | 1 | 15 |

Details:
- B10 legacy: explicit-Deny admin (confirmed), MFA-gated admin (confirmed), and two PassRole paths from `b10-passrole-conditioned` to those two roles (potential). This is the paper's 4 flagged paths in 3 cases.
- B10 annotate: the explicit-Deny admin path disappears (the role is inert). Two paths remain, both `unresolved` with `irsa_trust=invalid`: the MFA-gated admin bound directly, and PassRole from `b10-passrole-conditioned` to the MFA-gated admin. The 15 suppressed edges are all PassRole edges from `b10-explicit-deny-admin` (which has `Deny *`) to the other roles, logged as "explicit Deny on iam:PassRole".
- B10 strict: 29 suppressed = 15 explicit-Deny PassRole edges + 1 PassRole edge whose target's trust policy no service can satisfy (the MFA-gated target) + 13 IRSA edges whose role trust has no OIDC principal.
- B11 legacy: wildcard-principal admin (confirmed, IRSA-only), nested-conditions PassRole (potential), 5-hop chain (potential). Circular trust: 0 paths, no hang.
- B11 annotate: the three paths remain as `unresolved`, all with `irsa_trust=invalid`, and the wildcard-trust role is reported once as an exposure finding.
- B11 strict: no IRSA paths; exposure finding retained; 15 suppressed = 11 PassRole edges (target trust unusable) + 4 IRSA edges (no OIDC principal). The 11 PassRole edges were not inspected individually; inspect `evaluation/policy_semantics/live/b11_strict.json` (`suppressed_edges`) before quoting their origin.

Verification note: the first live run showed `exposure_findings=0` and no suppression log for strict mode, contradicting the offline replay. The cause was an early return in `main.run` that dropped those fields whenever no paths were found. The result dict is now built in one function used by both branches, with a unit test; the live run above is after that fix.

### 4.2 Offline replay

Cell format: confirmed / potential / unresolved paths; `+E1` = one wildcard-trust exposure finding. `conditional` = not decidable statically, excluded from scoring.

**B10 and B11, as-built fixtures (EC2 trust on every IRSA-bound role)**

| Case | Truth (author label) | Legacy | Annotate | Strict (default) |
|---|---|---|---|---|
| B10-01 s3-readonly | none | 0/0/0 | 0/0/0 | 0/0/0 |
| B10-02 ddb-readonly | none | 0/0/0 | 0/0/0 | 0/0/0 |
| B10-03 cw-readonly | none | 0/0/0 | 0/0/0 | 0/0/0 |
| B10-04 scoped-passrole | none | 0/0/0 | 0/0/0 | 0/0/0 |
| B10-05 logs-wildcard | none | 0/0/0 | 0/0/0 | 0/0/0 |
| B10-06 s3-scoped-star | none | 0/0/0 | 0/0/0 | 0/0/0 |
| B10-07 iam-readonly | none | 0/0/0 | 0/0/0 | 0/0/0 |
| B10-08 minimal | none | 0/0/0 | 0/0/0 | 0/0/0 |
| B10-09 ec2-describe | none | 0/0/0 | 0/0/0 | 0/0/0 |
| B10-10 safe-assume-chain | none | 0/0/0 | 0/0/0 | 0/0/0 |
| B10-11 scoped-group | none | 0/0/0 | 0/0/0 | 0/0/0 |
| B10-12 passrole-conditioned (PassedToService=ec2, Resource *) | none | 0/2/0 | 0/0/1 | 0/0/0 |
| B10-13 dangling-assume | none | 0/0/0 | 0/0/0 | 0/0/0 |
| B10-14 mfa-gated-admin (IRSA binds the admin role directly) | none | 1/0/0 | 0/0/1 | 0/0/0 |
| B10-15 explicit-deny-admin (IRSA binds the admin role directly) | none | 1/0/0 | 0/0/0 | 0/0/0 |
| B11-01 wildcard-principal-admin (IRSA binds it directly) | exposure | 1/0/0 | 0/0/1 +E1 | 0/0/0 +E1 |
| B11-02 nested-conditions PassRole | conditional | 0/1/0 | 0/0/1 | 0/0/0 |
| B11-03 5-hop chain | conditional | 0/1/0 | 0/0/1 | 0/0/0 |
| B11-04 circular trust (no admin) | none | 0/0/0 | 0/0/0 | 0/0/0 |

**B10 and B11, irsa-realistic fixtures (OIDC trust on ServiceAccount-bound roles)**

| Case | Truth (author label) | Legacy | Annotate | Strict (default) |
|---|---|---|---|---|
| B10-01 s3-readonly | none | 0/0/0 | 0/0/0 | 0/0/0 |
| B10-02 ddb-readonly | none | 0/0/0 | 0/0/0 | 0/0/0 |
| B10-03 cw-readonly | none | 0/0/0 | 0/0/0 | 0/0/0 |
| B10-04 scoped-passrole | none | 0/0/0 | 0/0/0 | 0/0/0 |
| B10-05 logs-wildcard | none | 0/0/0 | 0/0/0 | 0/0/0 |
| B10-06 s3-scoped-star | none | 0/0/0 | 0/0/0 | 0/0/0 |
| B10-07 iam-readonly | none | 0/0/0 | 0/0/0 | 0/0/0 |
| B10-08 minimal | none | 0/0/0 | 0/0/0 | 0/0/0 |
| B10-09 ec2-describe | none | 0/0/0 | 0/0/0 | 0/0/0 |
| B10-10 safe-assume-chain | none | 0/0/0 | 0/0/0 | 0/0/0 |
| B10-11 scoped-group | none | 0/0/0 | 0/0/0 | 0/0/0 |
| B10-12 passrole-conditioned (PassedToService=ec2, Resource *) | none | 0/2/0 | 0/1/0 | 0/0/0 |
| B10-13 dangling-assume | none | 0/0/0 | 0/0/0 | 0/0/0 |
| B10-14 mfa-gated-admin (IRSA binds the admin role directly) | none | 1/0/0 | 0/0/1 | 0/0/0 |
| B10-15 explicit-deny-admin (IRSA binds the admin role directly) | none | 1/0/0 | 0/0/0 | 0/0/0 |
| B11-01 wildcard-principal-admin (IRSA binds it directly) | exposure | 1/0/0 | 1/0/0 +E1 | 1/0/0 +E1 |
| B11-02 nested-conditions PassRole | conditional | 0/1/0 | 0/0/1 | 0/0/1 |
| B11-03 5-hop chain | conditional | 0/1/0 | 0/1/0 | 0/1/0 |
| B11-04 circular trust (no admin) | none | 0/0/0 | 0/0/0 | 0/0/0 |

How to read these:
- The as-built variant matches the live results in 4.1 path for path (annotate: 2 unresolved in B10, 3 in B11; strict: none).
- In the as-built variant the B10 MFA and Deny cases vanish under strict because IRSA trust is invalid, not because of the MFA or Deny logic. The irsa-realistic variant isolates those mechanisms: the all-Deny admin is inert, the MFA condition can never be satisfied by web identity (invalid trust), the conditioned-PassRole case has no usable admin target, and in annotate mode two paths survive as `potential`/`unresolved` (target unusable or trust invalid) that strict removes.
- B11-02 (nested conditions) becomes `unresolved` because `aws:RequestTag/...` cannot be evaluated statically. B11-03 (5-hop) stays `potential` because hop 1 is a bare PassRole.

**Summary over all 27 replay cases** (TP / FP / FN / TN; 4 `conditional` cases excluded). These counts include the 8 regression fixtures and **must not be cited as accuracy**.

| Fixture variant | Mode | Confirmed only | Confirmed + potential | All tiers incl. unresolved |
|---|---|---|---|---|
| as-built | legacy | 1/2/4/16 | 2/4/3/14 | 2/4/3/14 |
| as-built | annotate | 1/0/4/18 | 1/0/4/18 | 5/3/0/15 |
| as-built | strict | 1/0/4/18 | 1/0/4/18 | 1/0/4/18 |
| irsa-realistic | legacy | 1/2/4/16 | 2/4/3/14 | 2/4/3/14 |
| irsa-realistic | annotate | 5/0/0/18 | 5/2/0/16 | 5/3/0/15 |
| irsa-realistic | strict | 5/0/0/18 | 5/0/0/18 | 5/0/0/18 |

**Regression fixtures (irsa-realistic variant): code-path checks, not accuracy evidence**

| Case | Truth (author label) | Legacy | Annotate | Strict (default) |
|---|---|---|---|---|
| X-01 wildcard trust, caller may AssumeRole | exploitable | 0/0/0 | 1/0/0 +E1 | 1/0/0 +E1 |
| X-02 wildcard trust, caller lacks AssumeRole | none | 0/0/0 | 0/0/0 +E1 | 0/0/0 +E1 |
| X-03 wildcard trust gated by PrincipalOrgID | conditional | 0/0/0 | 0/0/1 +E1 | 0/0/1 +E1 |
| X-04 PassRole glob resource -> admin | exploitable | 0/0/0 | 1/0/0 | 1/0/0 |
| X-05 PassRole + paired action (lambda) -> admin | exploitable | 0/1/0 | 1/0/0 | 1/0/0 |
| X-06 PassRole to admin whose trust lists no service | none | 0/1/0 | 0/1/0 | 0/0/0 |
| X-07 admin with conditional Deny | conditional | 1/0/0 | 0/0/1 | 0/0/1 |
| X-08 correct IRSA admin (positive control) | exploitable | 1/0/0 | 1/0/0 | 1/0/0 |

### 4.3 Agreement with an independent policy matcher (PMapper)

PMapper 1.1.5 contains its own matcher for IAM policy statements (`policy_has_matching_statement`), written independently of CrossGuard. `evaluation/policy_semantics/differential/run_differential.py` generates random statements with a seeded generator (Allow/Deny; `Action`/`NotAction`; `Resource`/`NotResource`; exact, `*` and `?` patterns; conditions using the string, ARN, `Bool` and `Null` operators and their `IfExists` forms) and compares the two engines at two levels: whether a single statement matches a request, and the allow / deny / implicit-deny outcome of a whole policy of 1–4 statements. Every condition key used is either given a value or known-absent, so CrossGuard never needs to answer "unknown" on these cases. Run on the author's machine, seed 20260919, 20,000 cases per level:

| Run | Statement-level agreement | Policy-level agreement | Statements that match | PMapper outcomes (implicit deny / allow / deny) |
|---|---|---|---|---|
| Main, seed 20260919 | 19,789 / 20,000 (98.95%) | 19,568 / 20,000 (97.84%) | 1,943 (9.7%) | 15,296 / 2,990 / 1,714 |
| Controlled, seed 20260919 | 20,000 / 20,000 (100%) | 20,000 / 20,000 (100%) | 2,094 (10.5%) | 15,072 / 3,163 / 1,765 |
| Main, seed 1 | — | 98.89% / 97.75% | — | — |
| Main, seed 2 | — | 98.85% / 97.51% | — | — |
| Main, seed 3 | — | 99.01% / 97.64% | — | — |

Seeds 1–3 (20,000 cases each) were run to check stability: statement-level agreement ranged 98.85–99.01%, policy-level 97.51–97.75%, all four seeds attributed every disagreement to the same three causes below, and all four had zero unexplained policy-level disagreements. Full detail is reported for seed 20260919 (the run whose files are kept in the repo); the other three are summary-only. Run by the author (WSL, LocalStack 4.14.0, Minikube, PMapper 1.1.5), 2026-09-19/20.

The main run has 211 statement-level and 432 policy-level disagreements. Each statement-level disagreement was attributed by a targeted check (the differing component is isolated, and a cause is only claimed when re-running our evaluator with that one change makes it agree with PMapper). Four statements carry two causes, so the counts below sum to 215.

| Cause | Statements | What the two engines do | AWS documentation (to be verified, see below) |
|---|---|---|---|
| Resource ARN case | 159 | PMapper matches `Resource` patterns case-insensitively; CrossGuard matches case-sensitively | The Resource element documentation states that IAM user names in a Resource ARN are case-sensitive |
| ARN condition operator case | 20 | PMapper matches `ArnEquals`/`ArnLike`/`ArnNot*` case-insensitively; CrossGuard case-sensitively | The condition-operator documentation describes ARN matching as case-sensitive |
| `StringNotLike`, key absent | 36 | PMapper returns false; CrossGuard returns true | The documentation states that a negated operator such as `StringNotLike` is true when the key is absent from the request context |

No disagreement is left unexplained, and all 432 policy-level disagreements contain at least one statement-level disagreement, so the policy-level composition (Deny beats Allow, implicit deny) agrees with PMapper's. In the controlled run the two stimuli behind these causes are removed (case-variant ARN patterns and absent keys); the engines then agree on every case at both levels, across all `Action`/`NotAction`/`Resource`/`NotResource` forms and all supported condition operators. The per-operator rates in `differential_summary.json` count statements that contain the operator, not statements the operator caused to disagree, so an operator can show a non-zero rate because of another element of the same statement; the cause table is the attribution. Operators with no disagreement in the main run: `StringEquals`, `StringEqualsIgnoreCase`, `StringLike`.

Checks that the result means something:
- **Sensitivity.** A unit test (`tests/test_differential_sanity.py`) breaks the evaluator on purpose (inverting `StringEquals`) and requires the harness to report disagreements; it does.
- **Not a trivial agreement.** About 10% of statements match and about a quarter of policies produce an explicit allow or deny, so agreement is not merely both engines saying "no match".
- **Unsupported constructs.** IP, numeric and date operators, `ForAnyValue`/`ForAllValues` and policy variables return "unknown" rather than a definite answer (checked in every run).

What this does and does not show. It is evidence from a matcher we did not write that the layer deciding Deny and Condition outcomes behaves consistently with an independent implementation, and it located three places where the two differ. It is **not** ground truth: PMapper is not AWS, the generator covers only the features listed above, and it says nothing about IRSA trust matching or PassRole pairing (PMapper does not implement those the way CrossGuard does). The AWS-documentation column is a documentation reading. Confirming it on a real AWS account (for example with `iam:SimulatePrincipalPolicy`) has not been done. LocalStack's own simulator was tried and is not usable for this: it returned an internal error, and it would in any case be a reimplementation, not AWS.

## 5. Findings that affect the paper

1. **No IRSA-bound role in any existing benchmark has an OIDC trust policy.** A search of `benchmarks/` and `evaluation/` finds no `Federated` principal or `oidc-provider` anywhere. The trust policies inspected (B1 `admin-role`, B2 `role-a`, B8 `b8-admin` and `b8-role-shared`, every IRSA-bound role in B10 and B11) trust `ec2.amazonaws.com` or an AWS principal; the other benchmark scripts contain no `Federated` principal either. In real AWS a pod cannot assume such a role through IRSA, because `AssumeRoleWithWebIdentity` requires an OIDC trust. The IRSA-based positives in B1–B11 therefore measure whether the analyzer finds the annotation-to-admin structure, not whether a pod could really assume the role. This is the most important finding and must be disclosed.
2. **The original B10 and B11 results are reproduced exactly in legacy mode**, both live and offline. That confirms the documented false positives were caused by the mechanisms identified (Deny, MFA condition, PassedToService condition), and that the fixes act on those mechanisms.
3. **The B11 wildcard-trust "true positive" was correct for the wrong reason.** Under the new model the role is an exposure finding (publicly assumable admin), not an IRSA path.
4. **PassRole Resource globs were missed.** The original builder treated any Resource other than `"*"` as a literal ARN, so `arn:...:role/app-*` produced no edge (a false negative). Per-target evaluation fixes it.
5. **Parallel mechanisms were overwritten.** When two nodes were connected both by AssumeRole trust and by a PassRole grant, the later type replaced the earlier one. Cutting only the displayed mechanism does not sever the connection, so earlier remediation output could be incomplete for such pairs. Whether any existing benchmark contains such a pair has not been checked. The 40 remediation trials were run before this change.
6. **Broad-policy sources make the suppression log noisy.** A role with `Deny *` (or an `Allow *` admin) is evaluated against every other role for PassRole, producing one suppressed or accepted edge per target. This is correct but produces many log entries (15 in B10 annotate).
7. **The deployed web API (`crossguard-live-api`) calls `main.run`** and therefore now defaults to `strict`. Pass `semantics="legacy"` if the old behaviour is needed there.
8. **PMapper, the baseline tool in the paper, appears to deviate from documented AWS behaviour in three places** (section 4.3): case-insensitive ARN matching in `Resource` and in ARN condition operators, and `StringNotLike` with an absent key. This is a candidate finding based on the AWS documentation and on the differential test; it has not been confirmed on a real AWS account and should be worded as such if it is used in the paper. It does not affect the B1–B9 comparison, whose PMapper misses are explained by the escalation catalog and the missing IRSA edge.

## 6. Limitations and assumptions

- Truth labels in the replay are author-made. There is no independent oracle yet.
- The paired-action catalog is a working list and has not been cross-checked against the cited sources.
- Wildcard trust: an identity can use a `Principal:"*"` role only if its own policy allows `sts:AssumeRole` on it. This is the conservative reading (fewer false positives) and has not been checked against AWS documentation.
- Partial Deny on the admin sink is annotated, not used to downgrade admin.
- Not modelled: permission boundaries, SCPs, session policies, resource policies other than role trust policies, Deny inherited through IAM groups for users, unsupported condition operators and policy variables (these return unknown). L2 (SCPs and permission boundaries) stands.
- Unless `--oidc-provider-arn` is given, any OIDC provider principal in the trust policy is accepted. The existence and thumbprint of the provider are never checked.
- LocalStack may not resolve AWS-managed policy documents. `AdministratorAccess` is detected by ARN, so admin roles are still flagged, but a Deny inside an unresolved managed policy would be invisible. The B10 Deny case uses an inline policy and is unaffected.
- Wildcards in ARNs: CrossGuard uses a plain glob in which `*` can match across `:`. AWS documents that each colon-delimited ARN segment is checked separately, so unusual patterns (a `*` in the middle of a segment) may match differently. The differential generator does not cover this. Not yet probed.
- The differential test compares two implementations. The three points where they differ are resolved by reading the AWS documentation, not by running AWS.
- Scalability: the timed function `find_all_cross_layer_paths` is unchanged, so the O(n^2.012) measurement is unaffected. The builder does more work per PassRole source; ingestion time was already excluded from that claim.

## 7. Changes required in the paper text

- **Semantics label.** State which semantics produced each reported number. The confusion matrix (Table V), the 44 extracted configurations, the PassRole classification, the remediation trials and the BishopFox and Kubernetes Goat results were all produced in legacy mode.
- **Section III-F (IRSA bridge edge / C2).** The edge is still created from the annotation, but its role trust policy is now evaluated and recorded as `trust_status`; in strict mode an invalid trust suppresses the edge.
- **Section III-H (min-cut).** The unit cost is per node pair, regardless of how many mechanisms connect the pair; remediation lists every mechanism.
- **Table II (analyzed abstraction).** Move into "included": explicit Deny precedence, a Condition subset, wildcard trust, web-identity (OIDC) trust matching. Keep in "not evaluated": SCPs, permission boundaries, unsupported condition operators, session policies.
- **Section IV-A.** Add the confidence tiers (confirmed / potential / unresolved) and state that `unresolved` counts context-dependent findings separately.
- **Section IV-G/H (adversarial and false-positive tests).** Add the before/after results in 4.1 and the mechanism-isolating variant in 4.2. Re-describe the wildcard-trust case as an exposure finding.
- **Evaluation of the policy layer.** Add the differential test (section 4.3): agreement with an independent matcher, the three attributed causes, the positive control and the sensitivity check. State plainly that it is not ground truth.
- **Table XIII.** "Policy-condition eval." for CrossGuard changes from ✗ to partial (three-valued subset).
- **L1, L4, L7.** Rewrite as addressed, with the residual limits in section 6. L2 and L3 stay.
- **Threats to validity.** Add Finding 1: prior fixtures used non-OIDC trust on IRSA-bound roles.
- **Draft-text issues found while checking the paper.** Section V-A and limitation L6 cite the cross-cloud probe as "Section IV-F"; it is Section IV-I. (An earlier note that L1's "7 of the 12 true-positive-type paths" contradicted the "5 of 9" in Section IV-A was wrong: 12 = the 9 core true positives plus the 3 true-positive-type paths in B11, and 7 = 5 + 2, which agrees with the PassRole classification. The wording "across Sections IV-A and IV" should name IV-A and IV-G to be unambiguous.)

## 8. Not yet done (do not claim in the paper)

- An independent oracle and blind second labeller for ground truth at path level (the differential test in section 4.3 covers only the policy-matching layer).
- Confirming the three PMapper disagreements (section 4.3) on a real AWS account, and running the differential test with additional seeds.
- A larger generated benchmark with OIDC-realistic trust, hard positives and negatives, and a held-out set. **Done, section 10** -- 8,000 cases (4,000 dev + 4,000 held-out), 21 recipes, independent oracle, strict-vs-legacy sanity check, and a live LocalStack+Minikube sample (42/42 correct after fixing 7 harness-only bugs the offline check couldn't catch -- section 10.5).
- Real-world configurations evaluated with the repositories' actual IAM policies instead of synthetic roles. **Partially done, section 11** -- four verbatim published EKS-addon policies (5/5 correct offline; live verification not yet run) plus one Unit42-sourced pattern case. This is a small, high-provenance complement, not a systematic prevalence study across many repos, which remains open.
- Additional baselines (naive annotation-plus-admin-policy grep, IAM-Deescalate or IAMPERE if runnable) and min-cut ablations. **Done, section 12** -- naive baseline (0.40/0.29 precision/recall vs CrossGuard's 1.0/1.0 on identical sets), three min-cut ablations (greedy comparison, alternate-route, unreported-pair, plus a disjoint-chains sanity check), all with unit tests. IAM-Deescalate attempted but needs a live run in the author's WSL environment (not yet done); IAMPERE deliberately not attempted (disproportionate GNN/MaxSAT setup).
- Validation or downgrade of the risk score. **Done, section 13** -- empirically proved (with a regression-sensitive test) that remediation output is fully independent of the risk score's weights; searched for and found no authoritative external source that ranks these mechanisms by severity; recommended framing is an explicit downgrade to a triage/display heuristic.
- Re-running B1–B9, the 44 extracted configurations, remediation trials and the external targets under strict semantics with OIDC-realistic fixtures.

## 9. Reproduction

```
source venv/bin/activate
python -m pytest tests -q                              # 98 passed
python -m evaluation.policy_semantics.replay           # offline replay tables
python -m evaluation.policy_semantics.differential.run_differential 20000 20260919             # vs PMapper
python -m evaluation.policy_semantics.differential.run_differential 20000 20260919 controlled  # positive control
bash evaluation/policy_semantics/live_rerun.sh         # needs Docker, Minikube, awslocal; wipes LocalStack
python main.py --endpoint-url http://localhost:4566 --semantics strict --output-json out.json
```

`live_rerun.sh` resets the environment, runs the existing B10 and B11 setup scripts, creates the IRSA-annotated ServiceAccounts, runs `main.py` in all three modes, and `compare_live.py` prints the comparison and the legacy fidelity verdict. Outputs are in `evaluation/policy_semantics/live/`.
## 10. Large generated benchmark (independent, mechanically-derived labels)

*Status: complete offline, at scale. Live verification is a stratified sample (~40 cases), not full coverage -- see 10.5.*

### 10.1 Why

B1-B11 (9-15 cases total) were hand-labelled by the tool's own authors. The differential test in section 4.3 checks the policy-matching layer against an independent implementation, but says nothing about whether the tool correctly assembles a full path (IRSA trust + AssumeRole/PassRole chains + admin sink) or about the tool's scale on a realistic case count.

### 10.2 How truth is established without a human or a second tool

Each case is built from one of 21 **recipes** (`evaluation/generated_benchmark/generator.py`), grouped into four categories:

| Category | Meaning | Example recipes |
|---|---|---|
| `hard_positive` | a real path exists; CrossGuard should find it at the declared confidence tier | direct IRSA-to-admin, PassRole + a real paired action, 2-3 hop AssumeRole chains, PassRole Resource globs, partial Deny that doesn't neutralize admin |
| `hard_negative` | structurally close to a positive, broken by one specific thing | wrong IRSA trust subject, MFA-gated target, explicit `Deny */*`, PassRole `PassedToService` mismatch, PassRole to a role no service can assume, a specific Deny that cancels a wildcard PassRole grant, a broken link in an AssumeRole chain |
| `decoy` | looks like a positive at a glance but has no generated mechanism connecting entry to target | an admin role present in the graph with no edge to the entry ServiceAccount; a case with no IRSA annotation at all |
| `unresolved_by_design` | the correct static answer is "cannot be decided without runtime context" | a Deny gated on source IP; wildcard trust gated on `aws:PrincipalOrgID` |

Every IRSA-bound role gets a real OIDC federated trust statement (finding 1 of section 5: no B1-B11 fixture had one). Each case also gets 0-3 "noise" roles unconnected to the entry point, so a tool that pattern-matches on "an admin role is somewhere in the graph" would false-positive on them.

**The label is not "whatever CrossGuard says."** Each recipe declares its outcome (`reachable`, `confidence`, `target`, `mechanism`) at construction time, before the graph is built. `oracle.py` then independently re-derives the label straight from the generated policy JSON, using its own separately-written matching logic that imports nothing from `ingestion.policy_eval` or `graph.builder`. This catches disagreement between a recipe's stated intent and what its generated JSON actually says (generator bugs), which is a different failure mode than a shared misunderstanding of AWS semantics (checked separately against PMapper in section 4.3). See `oracle.py`'s module docstring for exactly what "independent" does and does not mean here.

### 10.3 Scale and generator/oracle agreement

Two splits, disjoint by construction (different seeds, checked by a unit test): a development set used while building the generator, and a fresh held-out set with a new seed, generated once the generator was frozen.

| Split | Seed | Cases | hard_positive | hard_negative | decoy | unresolved_by_design | Generator/oracle mismatches |
|---|---|---|---|---|---|---|---|
| dev | 30001 | 4,000 | 1,473 | 1,686 | 420 | 421 | 0 |
| heldout | 77777 | 4,000 | 1,473 | 1,684 | 421 | 421 | 0 (dev) [see 10.4] |

Zero mismatches on 8,000 cases means every generated fixture's raw JSON matches what its recipe declared it should say, as far as the independently-coded oracle can tell.

### 10.4 CrossGuard evaluated against the held-out set

`run_benchmark.py` builds one in-memory graph per case (same code path as `main.py`, no LocalStack) with `--semantics strict`, and scores each case: a `hard_positive` is a TP only if a path is found at the recipe's declared confidence tier (a right-answer-wrong-tier case is tracked separately as `TP_wrong_tier` and counted against recall, not silently folded into TP); an `unresolved_by_design` case is scored only on whether it was left un-confirmed (an early "confirmed" verdict on a genuinely undecidable case is the specific failure this category exists to catch).

| Split | Cases | TP | FP | FN | TN | TP (wrong tier) | Unresolved handled correctly | Unresolved wrongly confirmed | Precision | Recall |
|---|---|---|---|---|---|---|---|---|---|---|
| dev | 4,000 | 1,473 | 0 | 0 | 2,106 | 0 | 421 | 0 | 1.0000 | 1.0000 |
| heldout | 4,000 | 1,475 | 0 | 0 | 2,105 | 0 | 420 | 0 | 1.0000 | 1.0000 |

**Read this result narrowly.** A clean result here means the tool's own logic is internally consistent with the semantics it was built to implement (Deny, Conditions, IRSA trust, PassRole pairing -- the same mechanisms validated independently in section 4.3), at 8,000 cases instead of 9. It does **not** mean the tool is 100% accurate on real-world policies: every case here is synthetic, generated by the same understanding of AWS semantics the tool itself encodes, and the recipes are a closed set of 21 patterns, not an open-ended sample of what real IAM policies look like. A held-out split with a different seed still draws from the same 21 recipes -- it is a check for overfitting to specific random values, not for coverage. That is exactly the gap the next step (real-world evaluation with actual repository policies) is for.

**Sanity check that the harness can fail.** The same held-out set was run with `--semantics legacy` (the original, pre-fix evaluator) as a check that a genuinely worse tool gets a genuinely worse score, not that the harness always reports success:

| Semantics | Precision | Recall | FP | FN | Unresolved wrongly confirmed |
|---|---|---|---|---|---|
| strict (current) | 1.0000 | 1.0000 | 0 | 0 | 0 |
| legacy (pre-fix) | 0.4004 | 0.2865 | 632 | 1,051 | 210 / 421 |

Legacy mode gets roughly 40% precision and 29% recall on this benchmark and wrongly confirms half the `unresolved_by_design` cases, which is the expected result given the false positives documented in section 5 and the earlier B10/B11 findings. This is the harness's own equivalent of the sensitivity test in section 4.3.

### 10.5 Live sample -- run and verified (LocalStack 4.14.0, Minikube, WSL, 2026-09-19/20)

42 cases, 2 per recipe across all 21 recipes, run against real LocalStack + Minikube via `live_sample.py` / `check_live_case.py`, by the author (not offline). Final result after fixing the issues below:

| Outcome | Count |
|---|---|
| TP | 16 |
| TN | 22 |
| handled_correctly (unresolved_by_design) | 4 |
| FP | 0 |
| FN | 0 |

**42/42 correct.** No case category is skewed toward one outcome by luck: the count matches exactly 2 cases x 21 recipes, split as 8 hard_positive recipes -> 16 TP, 11 hard_negative recipes -> 22 TN, 2 unresolved_by_design recipes -> 4 handled_correctly (decoy recipes score as TN, folded into the 22).

**Getting here took seven rounds of fixes, all caught only by this live run** -- none of these were visible in the 8,000-case offline result in section 10.4, because that harness builds graphs from Python dicts directly and never touches LocalStack, Minikube, or real AWS ARNs. This is exactly why section 10.4 alone would have been an incomplete claim:

1. Policy documents need a top-level `"Version": "2012-10-17"` or LocalStack (and real AWS) reject them outright; the offline evaluator never checks this field.
2. Recipe-random namespaces (`prod`, `payments`, `ml-team`, ...) must exist in the cluster before a ServiceAccount can be created in them.
3. Recipe names containing `_` (e.g. `assumerole_chain_2hop`) leaked into generated ServiceAccount names, which Kubernetes requires to be RFC 1123 (`-` only, no `_`).
4. **The most consequential bug**: the generator used a fictional AWS account ID (`222233334444`) that LocalStack never actually assigns (its real default test account is `000000000000`). Every ARN embedded in generated trust and PassRole policies referenced the wrong account, so nothing CrossGuard ingested back from LocalStack ever matched -- every case whose detection depends on ARN matching (direct-admin, PassRole, AssumeRole chains) came back a false negative, while the one mechanism that doesn't need ARN matching (wildcard `Principal:"*"` trust) came back correct. That asymmetry in the failure pattern is what pinned this down.
5. The live-sample script only reset LocalStack once at the start, so roles from all 42 cases accumulated in one shared AWS account; a `decoy_rbac_only` case with no mechanism of its own was scored as a false positive because *some other* case's legitimate path existed somewhere in the (by then very large) shared account. Fixed by resetting LocalStack before every individual case, plus filtering found paths by the case's own entry-ServiceAccount node as a second layer of defense.
6. The live summary file was append-only and was never cleared between script runs, so a result like `n_cases: 84` after a 42-case run was actually two runs' results silently stacked together.
7. A PassRole `Resource` glob (`role/app-12345-*`) shares only a name *prefix* with its target role (`app-12345-admin`), not the full name; the case-renaming step (needed so many cases can share one LocalStack account without role-name collisions) only rewrote exact full-ARN matches, so the glob went stale after renaming and stopped matching its own target. Fixed by rewriting any `role/...*` glob to carry the case's renaming tag, generically, not just exact ARNs.

Bugs 1-3 and 6 are artifacts of the test harness (`live_sample.py`, `check_live_case.py`) -- they say nothing about CrossGuard. Bugs 4, 5 and 7 are more interesting: 4 and 7 are both instances of the same underlying risk (a rewrite step that only handles exact string matches will silently break any indirection -- an account ID standing in for "the account", a glob standing in for "a set of names"), and 5 is a reminder that testing many cases against one shared, stateful backend (one AWS account) can manufacture false positives that have nothing to do with the tool being tested. None of the seven represent a defect in `ingestion.policy_eval`, `graph.builder`, or `pathfinder.search` -- every fix was confined to `evaluation/generated_benchmark/{live_sample,check_live_case}.py`. The offline result in section 10.4 was not revised by any of this and needed no changes.

Reproduction:
```
python -m evaluation.generated_benchmark.live_sample --split dev --per-recipe 2 > /tmp/live_sample.sh
bash /tmp/live_sample.sh
cat evaluation/generated_benchmark/live/summary.json
```

### 10.6 Limitations

- The 21 recipes are a closed set the author designed; they do not sample the distribution of real-world IAM policies (that is section 4 -- not yet started -- real-world evaluation).
- The oracle re-implements AWS semantics independently of `policy_eval` but shares the same human's reading of the documentation; a shared misunderstanding would not be caught here (it is checked, for the policy-matching layer only, against PMapper in section 4.3).
- `run_benchmark.py` does not exercise `ingestion.aws_ingestion` / `ingestion.k8s_ingestion` (LocalStack/Minikube parsing) -- only `graph.builder` and `pathfinder.search`. Section 10.5's 42-case live sample checks the ingestion path and passed 42/42, but it is still a sample, not full live coverage of all 8,000 cases (see the note on cost in the original 10.5 design rationale).
- Noise roles are randomly shaped but drawn from a small pool of patterns (three kinds); they are a weaker adversarial check than a dedicated red-team benchmark would be.
- Scale (~4.9M generated policy statements across both splits, per the case counts above) has not been used to re-measure the O(n^2.012) scalability claim; these graphs are small per case (a handful of nodes), not one large graph.

### 10.7 Reproduction

```
python -m evaluation.generated_benchmark.generator --n 4000 --seed 30001 --split dev     --out evaluation/generated_benchmark/dev_cases.jsonl
python -m evaluation.generated_benchmark.generator --n 4000 --seed 77777 --split heldout --out evaluation/generated_benchmark/heldout_cases.jsonl
python -m pytest tests/test_generated_benchmark.py tests/test_live_sample.py -q      # 6 tests
python -m evaluation.generated_benchmark.run_benchmark --split dev
python -m evaluation.generated_benchmark.run_benchmark --split heldout
diff <(python -c "import json;print(json.load(open('evaluation/generated_benchmark/dev_results.json')))") \
     <(python -c "import json;print(json.load(open('evaluation/generated_benchmark/dev_results_reference.json')))")
     # should print nothing (byte-identical, verified by the author on a clean clone)

# live sample (needs Docker + Minikube; not yet run):
python -m evaluation.generated_benchmark.live_sample --split dev --per-recipe 2 > /tmp/live_sample.sh
bash /tmp/live_sample.sh
cat evaluation/generated_benchmark/live/summary.json
```

`*_cases.jsonl` are not committed (9+ MB, fully reproducible from the seed). `dev_results_reference.json` / `heldout_results_reference.json` are the author's own run, byte-identical to a regeneration on an independent clone (verified above).
## 11. Real-world evaluation with actual published policies

*Status: complete offline (5/5 correct). Live LocalStack verification not yet run -- see 11.4.*

### 11.1 Why this replaces the weakest tier of the original evaluation

The original RW-01-44 (referenced throughout this document) bound real ServiceAccount names and structure, extracted from public repositories, to synthetic test roles -- not to those repositories' actual IAM policies. The "manual production repos" tier (RW-33-40), the closest of the four extraction methods to a real-world test, is documented (in `evaluation/real_world/README.md`) as modeling misconfiguration *patterns* from Unit 42 threat reports, not using the projects' own published policies. RW-01-32 use a generic `over-privileged`/`correctly-scoped` flag with no sourced content at all. This section replaces that tier with genuinely sourced material: real IAM policy JSON fetched directly from four widely-deployed AWS EKS add-ons' own repositories, plus one case whose *pattern* (not exact policy) is sourced to a specific Unit 42 report.

Reused the existing `evaluation/real_world/RW_MANIFEST.md` repo list rather than searching fresh, per the author's preference to keep this comparable to the original 44.

### 11.2 The five cases

| Case | Source | Verbatim? | Declared truth |
|---|---|---|---|
| `RWP-aws-load-balancer-controller` | `kubernetes-sigs/aws-load-balancer-controller`, `docs/install/iam_policy.json` (`main` branch) | Yes -- fetched and transcribed in full | Not reachable (16 statements: ec2/elb/waf/acm/shield only, no admin/PassRole/AssumeRole) |
| `RWP-aws-ebs-csi-driver` | `kubernetes-sigs/aws-ebs-csi-driver`, `docs/example-iam-policy.json` (`master` branch) | Yes -- fetched and transcribed in full | Not reachable (ec2 volume/snapshot lifecycle, tag-conditioned) |
| `RWP-aws-efs-csi-driver` | `kubernetes-sigs/aws-efs-csi-driver`, `docs/iam-policy-example.json` (`master` branch) | Partial -- head/middle matched the fetched raw content; the tail two statements were reconstructed from search-snippet context because the full raw fetch was blocked mid-session. **Flagged for a manual byte-for-byte diff against the live URL before being cited as verbatim.** | Not reachable |
| `RWP-cluster-autoscaler` | Community gist (`gist.github.com/inductor/...`), cross-checked against the upstream project's FAQ.md pattern description | No -- a documented community policy, not the project's own repo file | Not reachable |
| `RWP-unit42-passrole-chain` | `unit42.paloaltonetworks.com/iam-roles-compromised-workloads/` -- pattern description only ("a risky combination of policies that allow users with an IAM role to elevate to AdministratorAccess") | No -- this is CrossGuard's own PassRole-plus-paired-action mechanism (already validated in sections 4 and 10) applied to a scenario matching the report's description, not an extracted policy | Reachable, confirmed (PassRole + `cloudformation:CreateStack` reaches an admin-labeled role) |

Each of the four negative cases is IRSA-bound with a valid OIDC trust statement (the same convention as every other fixture in this document) and nothing else added -- the real policy is the *only* content determining the result. A unit test (`test_negative_cases_have_no_admin_passrole_or_assumerole_action`) checks the four real policies don't themselves grant admin, PassRole, or AssumeRole, so a future upstream policy change that added one would fail loudly rather than silently keep a stale "always TN" expectation.

**Only one case here (`RWP-unit42-passrole-chain`) is not a verbatim published artifact**, and it is not presented as one anywhere in the code (its `fully_verbatim` field and a dedicated unit test both mark it `False`). It exists because Unit 42 describes the *pattern* of a real incident class, not the exact policy JSON from the account they investigated.

### 11.3 Offline result

`run_offline.py` builds one in-memory graph per case (same code path as `main.py`, `--semantics strict`) and checks it against the declared truth:

| Case | Declared | Found | Confidence | Outcome |
|---|---|---|---|---|
| RWP-aws-load-balancer-controller | not reachable | not found | -- | TN |
| RWP-aws-ebs-csi-driver | not reachable | not found | -- | TN |
| RWP-aws-efs-csi-driver | not reachable | not found | -- | TN |
| RWP-cluster-autoscaler | not reachable | not found | -- | TN |
| RWP-unit42-passrole-chain | reachable | found | confirmed | TP |

**5/5 correct.** Read this narrowly, the same way section 10.4's 8,000-case result should be: five cases is not a claim of broad real-world coverage, and four of the five are negatives by construction (real least-privilege policies are, definitionally, supposed to produce no path) -- the informative case is the single positive, and it rests on a sourced *pattern*, not an extracted incident. What this section adds over section 10 is that the policy *content* driving four of the five results is not something the author wrote, generated, or approximated -- it is what these specific, widely-deployed projects actually ship and recommend today.

### 11.4 Live verification -- run and confirmed (LocalStack, Minikube, WSL, 2026-09-20)

`live_verify.py` emits a script following the same pattern validated across seven fix rounds in section 10.5: per-case LocalStack reset, the real LocalStack test account, RFC-1123-safe names (these are the projects' own recommended ServiceAccount names, e.g. `ebs-csi-controller-sa`), every policy document carrying `"Version": "2012-10-17"` (true by construction -- these are the real, as-published documents), and a summary file cleared at the start of every run.

Run by the author:

```
python -m evaluation.real_world.published_policies.live_verify > /tmp/rwp_live.sh
bash /tmp/rwp_live.sh
cat evaluation/real_world/published_policies/live/summary.json
```

Result: `n_cases: 5`, `{"TN": 4, "TP": 1}` -- exactly matching the offline result in 11.3, case for case, with no fix cycles needed. Unlike section 10.5's seven-round history, this set has none of the properties that caused those bugs (no glob resources, no noise roles, and only 5 cases so cross-case contamination from a shared account was never in play), so this outcome is consistent with, not a coincidence against, that earlier experience.

### 11.5 Limitations

- Five cases, four of them structurally guaranteed negatives (a correctly-scoped published policy has no path by definition) -- this is not a claim about prevalence of misconfiguration in the wild, only about whether CrossGuard correctly recognizes a real least-privilege policy as safe and a documented escalation pattern as unsafe.
- `RWP-aws-efs-csi-driver`'s tail two statements need the manual verbatim check noted in 11.2 before the case is cited as extracted rather than reconstructed.
- `RWP-cluster-autoscaler` and `RWP-unit42-passrole-chain` are not verbatim project artifacts (see 11.2); this is disclosed in the case data itself (`fully_verbatim` field) and enforced by a unit test, not just stated here.
- No independent oracle or second labeller reviewed these five cases (per the author's constraint: no second person, no AWS account available) -- the truth labels are the author's own reading of each real policy's actions, checked only by the offline harness (which is the thing being evaluated) and, for the underlying policy-matching logic only, by the PMapper differential test in section 4.3.
- This does not replace the broader real-world evaluation still on the "not yet done" list below (systematic prevalence sampling across many repos); it is a small, deliberately high-provenance complement to it.

### 11.6 Reproduction

```
python -m evaluation.real_world.published_policies.run_offline
python -m pytest tests/test_real_world_published_policies.py -q      # 4 tests
python -m evaluation.real_world.published_policies.live_verify > /tmp/rwp_live.sh
bash /tmp/rwp_live.sh
cat evaluation/real_world/published_policies/live/summary.json
```
## 12. Baselines and ablations

*Status: complete, offline. IAM-Deescalate attempted but not run to completion in this environment (needs LocalStack, available only on the author's machine); IAMPERE deliberately not attempted (needs a GNN training pipeline and a MaxSAT solver deployment -- disproportionate to what a baseline comparison needs here). See `evaluation/baselines_and_ablations/EXTERNAL_TOOL_ATTEMPTS.md` for the full account of both.*

### 12.1 Naive baseline: "IRSA annotation + admin-labeled role, nothing else"

The most basic thing a team could write without any graph model: flag a ServiceAccount if its mapped role is admin-labeled, full stop -- no Deny, no Condition, no IRSA-trust check, no PassRole reasoning, no AssumeRole chain-following, no wildcard-trust modelling (`evaluation/baselines_and_ablations/naive_baseline.py`). Run against the exact same case sets already used to evaluate CrossGuard (section 10's generated benchmark, section 11's real-world set):

| Set | TP | FP | FN | TN | Precision | Recall |
|---|---|---|---|---|---|---|
| dev (n=4000) | 420 | 632 | 1053 | 1474 | 0.3992 | 0.2851 |
| heldout (n=4000) | 422 | 632 | 1053 | 1473 | 0.4004 | 0.2861 |
| RWP (n=5) | 0 | 0 | 1 | 4 | None | 0.0 |

CrossGuard scores 1.0/1.0 (section 10.4) and 5/5 (section 11.3) on these identical sets. The naive baseline's failure mode is symmetric and informative, not just "worse everywhere": it produces 632 false positives per 4,000-case split (flagging `direct_admin_wrong_subject`, `direct_admin_mfa_gated`, and `direct_admin_explicit_deny` cases, because it has no idea the role is actually unreachable or inert), while ALSO missing over 1,000 genuine escalations per split (every `passrole_*`, `assumerole_chain_*`, and `wildcard_trust_*` positive, because none of those have an admin-labeled role sitting directly behind the IRSA annotation -- reaching them requires exactly the cross-layer graph traversal that is this tool's core contribution). On the real-world set, it misses the one genuine escalation entirely (`RWP-unit42-passrole-chain`): the entry role isn't itself admin-labeled, so the naive check never looks past it.

### 12.2 Min-cut ablations

Three questions about `remediation/engine.py`'s min-cut, checked by direct code execution rather than left as unverified prose claims (`evaluation/baselines_and_ablations/mincut_vs_greedy.py`, 7 unit tests in `tests/test_baselines_and_ablations.py`):

**12.2.1 Does the global min-cut actually beat a naive greedy strategy on a shared bottleneck?** A greedy strategy (remove one edge per found path, independently, no cross-path reasoning -- the natural thing to do without solving a global min-cut) is compared against CrossGuard's min-cut on a constructed case where N independently-permitted ServiceAccounts all route through one shared hub role into one admin role:

| Shared-bottleneck entries | Paths found | Min-cut edges | Greedy edges |
|---|---|---|---|
| 2 | 2 | 1 | 2 |
| 3 | 3 | 1 | 3 |
| 4 | 4 | 1 | 4 |
| 8 | 8 | 1 | 8 |

Min-cut finds the single shared bottleneck edge regardless of N; greedy's edge count scales linearly with N. This is the same qualitative claim the paper's own B6/B8 benchmarks make ("2 paths closed by a single fix") but now measured directly against an explicit alternative, at scales the original benchmarks didn't test (up to 8 simultaneous callers).

**12.2.2 The paper's own caveat, checked: does an alternate route to the same (source, admin) pair, that Algorithm 1's BFS never reports (only the shortest route is returned per pair), actually survive the computed cut?** Section III-H of the paper states this "is not guaranteed." A case was built with one entry ServiceAccount and two entirely edge-disjoint routes to the same admin role -- a 2-hop direct route and a 4-hop chain through three intermediate roles, sharing only the entry and target nodes:

```
{
 "paths_found_for_this_source_admin_pair_by_pathfinder": 1,
 "reported_path_hops": 2,
 "all_simple_routes_in_full_graph": [
  [
   "sa-alt-route",
   "hub",
   "target-admin"
  ],
  [
   "sa-alt-route",
   "hub",
   "mid1",
   "mid2",
   "mid3",
   "target-admin"
  ]
 ],
 "min_cut_edges": [
  "sa-alt-route->hub"
 ],
 "long_route_(4_hop)_present_in_full_graph": true,
 "reported_path_set_contained_only_the_shortest_route": true,
 "src_still_connected_to_target_after_applying_the_computed_cut": false
}
```

The reported path set contains only the 2-hop route (confirmed: BFS returns one shortest path per pair, as documented). But the computed cut **does** sever the 4-hop alternate too (`src_still_connected_to_target_after_applying_the_computed_cut: false`), contradicting the "not guaranteed" wording as currently stated.

**Why, precisely:** `remediation/engine.py`'s `_build_super_graph` connects a super-source (infinite capacity) to every reported path's start node and a super-sink (infinite capacity) from every reported path's end node, then computes ONE min s*-t* cut using the graph's real edges (capacity 1 each). By standard max-flow/min-cut duality for a combined source/sink construction, this yields exactly the minimum edge cut separating the *union* of reported starts from the *union* of reported ends -- not merely the union of the individually reported paths' own edges. So the guarantee is stronger than Section III-H states, as long as both endpoints of the alternate route are each the start or end of *some* reported path.

Two more checks confirm this isn't an artifact of one lucky construction:

- **12.2.3 (ablation 2b) An entirely unreported (source, admin) *pair* -- not just an unreported route between an already-paired source and admin -- is severed too, whenever its source and its admin each individually appear as the endpoint of some other reported path**, even though the connection between them was never itself in the reported path set:

```
{
 "reported_pairs": [
  "sa-x->admin-x",
  "sa-y->admin-y"
 ],
 "cross_pair_(sa_x_to_admin_y)_individually_reported_by_pathfinder": false,
 "cross_pair_(sa_x_to_admin_y)_actually_connects_in_full_graph": true,
 "min_cut_edges": [
  "role/entry-y->admin-y",
  "sa-x->entry-x"
 ],
 "cross_pair_severed_by_the_computed_cut_despite_never_being_reported": true
}
```

- **12.2.4 (ablation 2c, sanity check) Genuinely disjoint escalation chains, sharing no node at all, correctly require two separate cuts, not one** -- confirming the above results aren't just the min-cut trivially collapsing to a single edge regardless of topology:

```
{
 "n_paths": 2,
 "min_cut_edge_count": 2,
 "min_cut_edges": [
  "role/entry-p->admin-p",
  "role/entry-q->admin-q"
 ],
 "correctly_requires_two_separate_cuts": true
}
```

**Scope of this correction.** The guarantee demonstrated here covers every (source, admin) pair that is *discovered at all* -- which, since Algorithm 1 iterates every `k8s_*`-typed node as a candidate source and BFS finds a shortest path to any reachable admin, is every pair with any real connectivity in the modeled graph. It does not extend past what section 5's L2 (SCPs, permission boundaries) already excludes, and it is demonstrated on four constructed graphs here, not proven for every conceivable topology -- the reasoning above (max-flow/min-cut duality for a combined-source/sink network) is what generalizes it beyond these four cases, not the cases themselves.

**Recommended change to the paper:** soften Section III-H's "the reported cut is not guaranteed to sever it" to something like "the cut is exact for the union of all reported source and admin nodes, including routes and pairs not individually reported; SCPs and permission boundaries remain unmodeled (L2)."

### 12.3 External tool baselines: attempted, not completed

See `evaluation/baselines_and_ablations/EXTERNAL_TOOL_ATTEMPTS.md` for the full account. Summary: **IAM-Deescalate** cloned and installed cleanly (lightweight dependencies), but its `audit` command requires a live AWS-or-LocalStack account graph built via PMapper, which needs Docker/LocalStack not available in this sandbox; exact commands to run it are provided for the author's WSL environment, where every other live verification in this document was actually run, but it has not been executed as of this writing. Expected result, based on the tool's documented scope (PMapper's graph plus a remediation layer, same missing Kubernetes/IRSA visibility already shown for PMapper directly in the paper's Section IV-C): no findings on any IRSA-mediated benchmark. **IAMPERE** was not attempted beyond confirming its repository exists and requires a GNN training pipeline and MaxSAT solver deployment -- a disproportionate side project for a baseline check, recorded as a deliberate scope decision.

## 13. Risk score: decoupling proof and external-anchor search

*Status: complete. Downgrade recommended and justified below rather than a numeric validation, since no numeric validation is available (no second person, no AWS account, and -- newly established here -- no authoritative external source ranks these specific mechanisms by severity either).*

### 13.1 What the risk score actually affects: proven by code inspection, then by execution

`scoring/risk.py`'s `score_all_paths` only attaches a `risk_score` to each already-found path and re-sorts the list for *display* order. `remediation/engine.py`'s `_build_super_graph` gives every real edge `capacity=1` regardless of type (line 147: `H.add_edge(u, v, capacity=1, **data)`) and never references `risk_score` anywhere in the file. So the tool's core correctness claim -- finding every escalation path and computing the minimum edge set that closes all of them -- is, by construction, independent of the risk score entirely.

This was verified empirically, not just asserted from reading the code (`evaluation/risk_score/decoupling_proof.py`, with a regression-sensitive unit test confirming the check can actually fail): the same four fixtures from section 12.2 were re-scored under three weight sets -- the production weights, a flattened set, and a set with the relative order of `irsa_bridge`/`PassRole`/`AssumeRole` deliberately inverted -- and the remediation output (the *set* of cut edges) was compared:

| Fixture | Paths | Cut edges identical across production/flattened/adversarial weights? |
|---|---|---|
| shared_bottleneck_4 | 4 | True |
| alternate_route | 1 | True |
| unreported_pair | 2 | True |
| disjoint | 2 | True |

**Identical cut-edge sets in all four cases, across all three weightings.** Only the numeric `risk_score` values attached to each path changed. A dedicated test (`test_risk_score_decoupling_detects_a_real_regression`) confirms this isn't a vacuous pass: it rigs remediation to depend on the top-scored path (simulating what a risk-score-dependent implementation would do) on a fixture specifically built so production and inverted weights rank the two paths oppositely, and confirms the harness then correctly reports *different* cut sets -- i.e., the check is capable of failing when the property it tests is actually false.

**What this changes for the paper's risk-score limitation.** "The risk score's weights are unvalidated heuristics" is true (see 13.2) and was already partly conceded in the paper's own Section IV-F ("a useful heuristic, not a formally invariant metric"). But the concrete consequence of that fact is now bounded precisely: it affects only the *order* findings are presented to a user, never whether a path is found or whether the computed remediation actually closes every found path. That is a substantially narrower liability than "the tool's remediation depends on an unvalidated score" would be.

### 13.2 Searched for an external severity ranking to validate the weight order against -- none exists

The production weights order mechanisms as `irsa_bridge (3.0) > PassRole (2.5) > AssumeRole (2.0) > rbac_binding (1.5) > group_membership (1.0)`. A search for an authoritative external source ranking these specific mechanisms by severity (Rhino Security Labs' catalog, Cloudsplaining's privilege-escalation glossary, and a sample of static-analysis tool severity scores) found **no such ranking**. Rhino's own writeups for `PassRole+RunInstances`, `PassRole+Lambda`, and `UpdateAssumeRolePolicy+AssumeRole` each independently state impact "could range from no privilege escalation to full administrator access" -- i.e., severity is explicitly framed as depending on *what's reachable*, not on which mechanism was used. Cloudsplaining's glossary sources the same Rhino catalog without adding a ranking. A KICS query for one specific `glue:CreateDevEndpoint`+`PassRole` combination carries a numeric `Risk score: 6.8`, but that is KICS's own internal scale for one specific finding type, not a general ranking of mechanisms comparable to CrossGuard's five edge-type weights.

**Conclusion: no numeric or ranked external validation is available for this weight order**, not because it wasn't looked for, but because the closest analogous sources deliberately avoid making exactly this kind of claim. Combined with section 13.1's decoupling result, the recommended framing for the paper is a downgrade, not a validation:

**Recommended paper text change:** describe `PERMISSION_WEIGHTS` and `score_path` explicitly as a **triage/display-ordering heuristic**, state plainly that no authoritative external source was found to validate the specific relative weights against (searched: Rhino Security Labs, Cloudsplaining), and state that remediation completeness and correctness -- the tool's actual accuracy claims, evaluated in sections 4, 10, and 11 -- do not depend on it in any way (cite section 13.1's empirical proof). The existing Section IV-F sensitivity analysis (pairwise ranking agreement under alternate weightings) can stay as supporting evidence that the heuristic is at least internally stable, but should no longer be the paper's main defense of the score -- that defense is now the decoupling proof.

### 13.3 Reproduction

```
python -m evaluation.baselines_and_ablations.run_naive_baseline
python -m evaluation.baselines_and_ablations.mincut_vs_greedy
python -m evaluation.risk_score.decoupling_proof
python -m pytest tests/test_baselines_and_ablations.py -q      # 9 tests
```
