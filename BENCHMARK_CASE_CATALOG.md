# CrossGuard Benchmark Case Catalog

*This document is the authoritative accounting of every test case used to evaluate CrossGuard. For any case category, it states what the cases are, why that category exists, where its scenarios come from, how ground truth was established, what the result was, and exactly where to find the code and raw results. Every count below is drawn from a file that exists in the repository, not quoted from memory or from prose elsewhere.*

**Last verified:** 2026-09-24, on `~/projects/iam-k8s-privesc`.

---

## Methodology and provenance

**There is no standard, shared benchmark dataset for cross-layer AWS IAM and Kubernetes RBAC privilege escalation.** This is the documented state of the field, not a gap specific to this evaluation. TAC (Hu & Wang), cited in this project's related-work review, states its own motivation for building a 2,500-case synthetic benchmark plainly: no existing benchmark "matched the scale and complexity of real-world cases," so one had to be constructed. Every AWS IAM privilege-escalation tool surveyed in the related-work review (PMapper, Cloudsplaining, Pacu, TAC) evaluates itself against either a purpose-built synthetic benchmark or the one externally published benchmark the field does have — BishopFox's *IAM Vulnerable* (31 documented scenarios) — never a shared standard dataset, because none exists.

Given that, every test case in this catalog traces back to one of three sources, stated explicitly per category below:

1. **A published, external benchmark.** *IAM Vulnerable* is used elsewhere in the literature for exactly this purpose — the CloudExploit paper and IAM-Deescalate's own published evaluation both use it. This project uses the same benchmark, as published, in category 5.
2. **A documented taxonomy of real AWS IAM escalation techniques.** Rhino Security Labs' catalog of AWS privilege-escalation methods (Spencer Gietzen, 2019) is the taxonomy that PMapper, Cloudsplaining, and Pacu each build their own detection logic against. It is the source this project draws from for *which* mechanisms to test — a bare `iam:PassRole` grant paired with a completing action, an `sts:AssumeRole` trust chain, and so on are documented, real techniques, not invented ones.
3. **AWS's own published IAM semantics**, for correctness at the level of individual policy evaluation — what a `Deny` overrides, what a condition operator does when its key is absent, how trust-policy web-identity federation matches a subject. This level is checked independently against a second, unrelated implementation in category 11, rather than against a taxonomy of attack techniques: it is a question of whether the policy evaluator agrees with a real, independently-written one, not whether a scenario "looks like" a known attack.

**What is, and is not, externally sourced.** The specific graphs, role names, and JSON policy documents making up each test case are this project's own construction — no library of ready-made cross-layer IAM+RBAC test graphs exists to draw from, which is again a field-wide gap. What is externally grounded is (a) which mechanisms and edge cases are worth testing at all (source 2), (b) whether the tool's evaluation of those mechanisms is correct (source 3, checked independently in category 11), and (c) one full external scenario set used exactly as published (source 1, categories 5 and 9). Each category below states which of these applies.

---

## Master summary

| # | Category | Cases | Scenario provenance | Ground truth method |
|---|---|---|---|---|
| 1 | Core detection scenarios (B1–B9) | 9 | Constructed to instantiate documented mechanisms from the Rhino Security Labs technique taxonomy | Constructed and labeled by the author |
| 2 | False-positive stress suite (B10) | 15 | Constructed to test AWS-documented IAM semantics (Deny, Condition, MFA) that a naive detector commonly gets wrong | Constructed and labeled by the author |
| 3 | Adversarial/evasion suite (B11) | 4 | Constructed to test evasion patterns (wildcard trust, nested conditions, long chains, cyclic trust) | Constructed and labeled by the author |
| 4 | Real-world extracted configurations (RW-01–44) | 44 | Real ServiceAccount structure extracted from 30+ public repositories via six mechanical extraction methods, bound to controlled test roles | Constructed and labeled by the author |
| 5 | Supplemental environment checks | 3 | BishopFox's published *IAM Vulnerable* benchmark, used as published; Kubernetes Goat and OWASP EKS Goat, published Kubernetes-security training environments | Outcome labeled by the author |
| 6 | Policy-semantics regression fixtures (X-01–X-08) | 8 | Each targets one specific AWS-documented IAM condition-operator or trust-policy semantic | Constructed by the author |
| 7 | Generated benchmark — development split | 4,000 | 21 recipes, 19 instantiating a documented mechanism or semantic, 2 robustness controls | Constructive labeling, independently re-checked by a separate oracle module |
| 8 | Generated benchmark — held-out split | 4,000 | Same as above, disjoint seed | Same as above |
| 9 | Real-world published-policy set (RWP) | 5 | Verbatim policies published by four widely-deployed open-source projects, plus one case modeling a pattern documented in a public industry threat report | Verbatim external artifacts; one sourced pattern |
| 10 | Min-cut ablation graphs | 7 | Constructed to test a specific, mathematically-justified algorithmic property, not an attack technique | Constructed to test a specific property |
| | **Total labeled accuracy cases** | **8,095** | | |

Two further evaluations sit outside this table because they check something other than case-by-case detection accuracy, documented with the same rigor in their own sections: a differential test of the policy-matching layer against an independent implementation (category 11), and an empirical proof that the remediation algorithm's output does not depend on the risk-scoring heuristic (category 12).

---

## 1. Core detection scenarios (B1–B9)

**What these are.** Nine scenarios exercising the tool's core mechanics one property at a time: a direct IRSA-to-admin escalation (B1), a multi-hop IRSA→PassRole→AssumeRole chain (B2), five ServiceAccounts with exactly one vulnerable (B3), two true-negative controls scoped to rule out same-layer and single-role false positives (B4, B5), a shared-bottleneck pair reachable at two different path lengths (B6-far, B6-near), a cross-namespace RBAC-only negative with no AWS-side component (B7), a case constructed so a single `iam:PassRole` grant is the unique global-min-cut edge (B8), and four near-miss multi-hop cases pairing real extracted ServiceAccount names with genuinely partial-privilege roles (B9).

**Where these scenarios come from.** Each instantiates a documented, real AWS IAM escalation mechanism. B2, B6, and B9's `iam:PassRole`-chained escalations instantiate the PassRole-based techniques in Rhino Security Labs' catalog — the same catalog PMapper, Cloudsplaining, and Pacu build their own detection against. B1 instantiates the direct-assumption baseline every one of those tools also checks. B4, B5, and B7 are constructed negatives scoped specifically to rule out the false-positive patterns a same-layer or single-layer analyzer would produce, which is the structural gap identified against prior tools (PMapper, Cloudsplaining) in this project's own related-work comparison.

**Ground truth.** Constructed and labeled by the author. A verdict of "TP" here means an admin-labeled principal was reached under the tool's own admin-detection heuristic, not a formally verified guarantee of live AWS administrator access — five of the nine true positives rest on a bare `iam:PassRole` grant, not independently exploitable in real AWS without a paired completing action, and those five are labeled Conservative-Potential rather than Confirmed throughout the result reporting.

**Result.** 9/9 labeled outcomes matched (14 path-level outcomes across the 9 scenarios, since B8 and B9 each contain multiple paths): TP=9 (4 Confirmed, 5 Conservative-Potential), TN=5, FP=0, FN=0.

**Files.** `benchmarks/bench1/` through `benchmarks/bench9/`, `evaluation/benchmarks_raw/`.

**Reproduce.**
```
bash benchmarks/reset_environment.sh
bash benchmarks/bench1/setup_aws.sh   # ... through bench9
python main.py --endpoint-url http://localhost:4566
```

---

## 2. False-positive stress suite (B10)

**What this is.** Fifteen configurations designed to be safe — no admin-labeled role is genuinely reachable in any of them — probing the specific AWS IAM semantics a detector without full policy evaluation commonly gets wrong: five standard read-only policy patterns (S3, DynamoDB, CloudWatch, IAM-read, EC2-describe), a resource-scoped PassRole grant (B10-04), a wildcard action scoped to a single resource (B10-06), a minimal identity holding only `sts:GetCallerIdentity` (B10-08), a safe two-role AssumeRole chain ending in a non-admin role (B10-10), a bare IAM group with no ServiceAccount binding (B10-11), a dangling AssumeRole permission with no IRSA annotation (B10-13), and three deliberately adversarial edge cases: a `PassRole` grant gated by an `iam:PassedToService` condition with no redundant trust path (B10-12), an admin role with an explicit `Deny *` on `*` that AWS's own policy evaluation makes inert (B10-15), and an admin role whose trust policy requires `aws:MultiFactorAuthPresent:true`, a condition IRSA/OIDC federation can never satisfy (B10-14).

**Where these scenarios come from.** Each targets a specific, AWS-documented policy-evaluation rule: explicit-Deny precedence, the `iam:PassedToService` condition key's documented behavior, and the documented fact that web-identity federation never presents an MFA context. These are not attack techniques from source 2 — they are the AWS semantics whose edge cases are the most common source of false positives in a static analyzer that does not fully evaluate policy conditions.

**Ground truth.** Constructed and labeled by the author, against AWS's own condition-operator and policy-evaluation documentation.

**Result.** All fifteen correctly produce zero findings.

**Files.** `benchmarks/bench10/`, `evaluation/benchmarks_raw/benchmark10_result_v2.json`.

**Reproduce.**
```
bash benchmarks/reset_environment.sh
bash benchmarks/bench10/setup_aws.sh
python main.py --endpoint-url http://localhost:4566
```

---

## 3. Adversarial/evasion suite (B11)

**What this is.** Four cases constructed to stress-test patterns a skeptical reviewer would specifically probe: a wildcard trust principal (`Principal: "*"`) on an admin-labeled role (B11-01), deeply nested and combined policy conditions on the escalation-relevant policy (B11-02), an obfuscated five-hop escalation chain (B11-03), and a circular trust relationship between two non-admin roles, testing that path discovery terminates safely on a cycle rather than hanging (B11-04).

**Where these scenarios come from.** B11-01 and B11-03 instantiate documented Rhino Security Labs techniques (wildcard/overly-permissive trust, multi-hop chaining) at their most adversarial. B11-02 targets AWS's own condition-operator semantics under combination, the same source-3 grounding as category 2. B11-04 is a robustness control on the pathfinding algorithm itself, not an attack technique — it tests termination, not detection.

**Ground truth.** Constructed and labeled by the author.

**Result.** 4/4 cases resolve with the expected graph-level behavior; the circular-trust case completes with no hang, confirming safe termination on cyclic input.

**Files.** `benchmarks/bench11/`, `evaluation/benchmarks_raw/benchmark11_result.json`.

**Reproduce.**
```
bash benchmarks/reset_environment.sh
bash benchmarks/bench11/setup_aws.sh
python main.py --endpoint-url http://localhost:4566
```

---

## 4. Real-world extracted configurations (RW-01–44)

**What this is.** Forty-four ServiceAccount and role configurations, extracted from over 30 distinct public GitHub repositories via six mechanical extraction methods (literal-plus-`values.yaml` resolution; Helm template rendering with the real Helm engine; Terraform HCL parsing; Terraform module call-site resolution; four manually-selected production repositories with hand-verified real and correctly-scoped policy variants; and four near-miss multi-hop cases reusing the B9 fixtures' real extracted ServiceAccount names), each bound to a controlled test role labeled either over-privileged or correctly-scoped.

**Where these scenarios come from.** The ServiceAccount names, namespaces, and structural shape in every one of the 44 cases are real — extracted mechanically from real, currently-public repositories (a full per-repository manifest is in `evaluation/real_world/RW_MANIFEST.md`), never fabricated or derived from a repository name as a fallback. The role content each ServiceAccount is bound to is a controlled test fixture (`over-privileged` or `correctly-scoped`, or, for four of the manually-selected cases, `AdministratorAccess` versus a specific scoped policy such as ELB read-only or Route53 DNS01-only) constructed by the author to model a realistic misconfiguration class, not extracted from that repository's own deployed IAM policy — this is stated so a reader does not read a result here as a claim about any specific repository's actual security posture.

**Ground truth.** Constructed and labeled by the author, per the role fixture assigned to each real ServiceAccount.

**Result.** 44/44 correct, 0 false positives, 0 false negatives, all produced by a live, fresh re-run against LocalStack and Minikube for every row (not reconstructed from notes).

**Files.** `evaluation/real_world/RW_MANIFEST.md` (full per-case record), `evaluation/real_world/README.md` (extraction methodology), `evaluation/real_world/final_evaluation_summary.md`.

**Reproduce.** Per-method setup scripts and raw result JSONs are referenced by ID in `RW_MANIFEST.md`.

---

## 5. Supplemental environment checks

**What this is.** Three checks against fully external, published environments, not author-constructed scenarios at all:

- **BishopFox's *IAM Vulnerable*** (265 Terraform-deployed resources, 31 documented attack scenarios): a ServiceAccount was IRSA-bound to one of its documented three-hop AssumeRole escalation scenarios; the full path was correctly detected in a 3.03-second scan of the complete 243-node, 1,338-edge deployment.
- **Kubernetes Goat's `insecure-rbac` scenario**: a cluster-admin-bound ServiceAccount, augmented with an IRSA annotation to model a realistic compounding misconfiguration; the resulting cross-layer edge was correctly detected.
- **OWASP EKS Goat**: whose documented attack surface (ECR image backdooring, IMDSv2 credential theft) contains no `eks.amazonaws.com/role-arn` annotations anywhere in its manifests; correctly reported as zero cross-layer paths, evidence of correct scoping to the IRSA threat model rather than a detection gap.

**Where these scenarios come from.** All three are used exactly as published by their respective maintainers (BishopFox, Madhu Akula, OWASP), with only the minimal augmentation stated above (an IRSA annotation added to model the cross-layer scenario these tools do not themselves cover, since none of the three natively models AWS IAM/Kubernetes federation).

**Ground truth.** Determined by each environment's own published documentation of its attack surface (BishopFox's documented escalation scenarios; Kubernetes Goat's and OWASP EKS Goat's documented vulnerabilities), not by the author.

**Files.** Referenced in the project's evaluation results under the corresponding external-target result files.

---

## 6. Policy-semantics regression fixtures (X-01–X-08)

**What this is.** Eight targeted fixtures, each isolating one specific AWS IAM condition-operator or trust-policy semantic: wildcard trust where the caller may or may not itself call `sts:AssumeRole` (X-01, X-02), wildcard trust gated by `aws:PrincipalOrgID`, genuinely undecidable without runtime context (X-03), a PassRole Resource glob matching a target role by wildcard (X-04), PassRole paired with a real completing action reaching an admin role (X-05), PassRole to an admin role whose trust policy names no assumable service, so the grant is structurally unusable (X-06), an admin role with a conditional Deny (X-07), and a positive control confirming the basic direct-IRSA-to-admin case still works under the full evaluator (X-08).

**Where these scenarios come from.** Each is built to isolate exactly one AWS-documented policy-evaluation rule (source 3), deliberately minimal so a failure in any one of them points unambiguously at the specific mechanism responsible, rather than at a compound scenario where multiple mechanisms interact.

**Ground truth.** Constructed by the author against AWS's own condition-operator and trust-policy documentation.

**Result.** 8/8 correct under the full policy evaluator.

**Files.** `evaluation/policy_semantics/replay.py` (fixture definitions), `evaluation/policy_semantics/POLICY_SEMANTICS_EVALUATION.md`.

**Reproduce.**
```
python -m evaluation.policy_semantics.replay
```

---

## 7. Generated benchmark — development and held-out splits

**What this is.** 8,000 synthetic AWS IAM + Kubernetes RBAC graphs — 4,000 development, 4,000 held-out with an independent seed — built from 21 fixed recipes spanning four categories:

| Category | Count (development / held-out) | Meaning |
|---|---|---|
| Hard positive | 1,473 / 1,475 | A real escalation path exists; must be found at the recipe's declared confidence tier |
| Hard negative | 1,686 / 1,684 | Structurally close to a positive, broken by one specific mechanism (a wrong IRSA trust subject, an MFA gate, an explicit Deny, a PassRole target no service can assume, a Deny that cancels a wildcard PassRole grant, a broken link in an AssumeRole chain) |
| Decoy | 420 / 421 | Resembles a positive at a glance — an admin-labeled role present in the graph, or no IRSA annotation at all — with no mechanism actually connecting the entry point to it |
| Unresolved by design | 421 / 420 | The correct static answer genuinely cannot be decided without runtime context (an IP-address condition, an org-ID-gated wildcard trust), and must be reported as such rather than silently confirmed or dropped |

**Where these recipes come from and why 21, not some other number.** This is the count of distinct mechanisms this project identified as needing dedicated coverage. 19 of the 21 recipe categories each instantiate one specific documented mechanism or semantic, drawn from the same two sources as the core scenarios in category 1: documented AWS IAM escalation techniques (source 2 — direct assumption, PassRole with a paired action, PassRole without one, multi-hop AssumeRole chains, wildcard-principal trust) and documented AWS IAM policy semantics whose edge cases are known sources of false positives or false negatives in naive tooling (source 3 — explicit Deny precedence, condition operators evaluated against an absent key, MFA-gated trust, a `PassedToService` condition, resource-ARN globbing). The remaining 2 (`decoy_unreachable_admin`, `decoy_rbac_only`) are not technique instantiations — they are robustness controls, testing that detection requires an actual connecting mechanism rather than the mere co-presence of an admin-labeled role and an IRSA annotation in the same graph, the specific false-positive pattern that motivated the naive-baseline comparison in category 13. The generator module's own docstring records each recipe against what it targets; see `evaluation/generated_benchmark/generator.py`.

**Why this case volume.** The precedent for a purpose-built synthetic benchmark at this scale, in exactly this research area, is TAC-Bench (2,500 cases, built for the same reason: no existing benchmark matched the needed scale). This benchmark extends the same methodology — a small number of documented mechanisms, each instantiated many times with randomized naming, structure, and surrounding noise, so detection accuracy can be reported as a statistic across a broad structural space rather than illustrated by a handful of examples.

**Ground truth.** Each recipe declares its intended outcome as part of construction — the label is data attached at construction time, not inferred afterward. A separate module, `oracle.py`, independently re-derives the correct answer directly from each case's raw generated policy JSON, using its own matching logic that shares no code with the analyzer being evaluated. This checks that a case's generated content matches what its recipe intended to build: 0 mismatches across all 8,000 cases. Whether the underlying policy semantics are themselves correct is checked separately, against a real independent implementation, in category 11.

**Result:**

| Split | TP | FP | FN | TN | Unresolved handled correctly | Unresolved wrongly confirmed | Precision | Recall |
|---|---|---|---|---|---|---|---|---|
| development | 1,473 | 0 | 0 | 2,106 | 421 | 0 | 1.0000 | 1.0000 |
| held-out | 1,475 | 0 | 0 | 2,105 | 420 | 0 | 1.0000 | 1.0000 |

Read narrowly: this shows the tool's detection logic is internally consistent with the documented AWS mechanisms and semantics it is built to cover, across a broad structural space. It is not a claim about the prevalence of misconfigurations in arbitrary real-world policies, which is addressed separately by category 9.

**Live-verified.** A stratified sample of 42 cases (2 per recipe) was run against real LocalStack and Minikube instances, confirming the tool's ingestion and graph-construction path, not just its algorithmic core, behaves correctly end to end. Result: 42/42 correct (16 TP, 22 TN, 4 handled-correctly, 0 FP, 0 FN), matching the in-memory result case for case.

**Files.** `evaluation/generated_benchmark/generator.py`, `oracle.py`, `run_benchmark.py`, `live_sample.py`, `dev_results_reference.json` / `heldout_results_reference.json`.

**Reproduce.**
```
python -m evaluation.generated_benchmark.generator --n 4000 --seed 30001 --split dev     --out evaluation/generated_benchmark/dev_cases.jsonl
python -m evaluation.generated_benchmark.generator --n 4000 --seed 77777 --split heldout --out evaluation/generated_benchmark/heldout_cases.jsonl
python -m evaluation.generated_benchmark.run_benchmark --split dev
python -m evaluation.generated_benchmark.run_benchmark --split heldout
python -m evaluation.generated_benchmark.live_sample --split dev --per-recipe 2 > /tmp/live.sh && bash /tmp/live.sh
```

---

## 9. Real-world published-policy set (RWP)

**What this is.** Five cases built from real IAM policy content rather than a synthetic test fixture bound to a real ServiceAccount name (the approach in category 4). Four are the actual, currently-published least-privilege IAM policies of widely-deployed AWS EKS add-ons, fetched directly from each project's own repository: the AWS Load Balancer Controller, the AWS EBS CSI Driver, the AWS EFS CSI Driver, and Cluster Autoscaler. The fifth models a specific pattern documented in Unit 42's "Misconfigured IAM Roles Lead to Thousands of Compromised Cloud Workloads" report — a role reachable via a `PassRole`-plus-paired-action chain to an admin-labeled role, the general pattern the report describes as "a risky combination of policies that allow users with an IAM role to elevate to AdministratorAccess."

**Where these scenarios come from.** The four negative cases are verbatim, as-published policy documents — not modeled, not approximated. Each is checked by a dedicated test that the real policy contains no admin, PassRole, or AssumeRole grant, so a future upstream policy change adding one would fail loudly rather than silently keep a stale expectation. The fifth case is explicitly disclosed, in the case data itself and in a dedicated test, as not a verbatim artifact — it is this project's own construction of the pattern Unit 42 describes, since Unit 42 does not publish the exact policy JSON from the account it investigated.

**Ground truth.** For the four verbatim cases: a correctly-scoped, real, published least-privilege policy has no path by definition — reachability is not reachable. For the fifth: reachable, at confirmed confidence, per the sourced pattern.

**Result.** 5/5 correct, both in an in-memory graph and against real LocalStack and Minikube.

**Files.** `evaluation/real_world/published_policies/policies.py` (verbatim policy text with source URLs), `build_cases.py`, `run_offline.py`, `live_verify.py`.

**Reproduce.**
```
python -m evaluation.real_world.published_policies.run_offline
python -m evaluation.real_world.published_policies.live_verify > /tmp/rwp_live.sh && bash /tmp/rwp_live.sh
```

---

## 10. Min-cut ablation graphs

**What this is.** Seven constructed graphs, not attack scenarios, built to test specific properties of the remediation algorithm directly rather than leave them as prose claims: a shared-bottleneck case at four scales (2, 3, 4, and 8 simultaneous callers routed through one shared role), confirming the global min-cut finds the single shared edge regardless of scale while a naive greedy per-path strategy scales linearly; an alternate-route case (one entry point, two edge-disjoint routes of different lengths to the same admin role), confirming the computed cut severs a longer route the path-discovery algorithm never individually reports; an unreported-pair case, confirming the cut also severs a connection between a source and an admin role that were never paired together in any single reported path, as long as each individually appears as the endpoint of some other reported path; and a disjoint-chains sanity check, confirming two genuinely unconnected escalation chains correctly require two separate cuts rather than the algorithm trivially collapsing to one edge regardless of topology.

**Where these scenarios come from.** These are not instances of a documented attack technique — they test a specific, provable property of the minimum-cut construction (`remediation/engine.py`), justified by standard max-flow/min-cut duality for a combined super-source/super-sink network, not merely by the seven constructed cases themselves.

**Ground truth.** The expected outcome for each is derived from the mathematical property being tested, not labeled by inspection.

**Result.** All seven confirm the intended property. The alternate-route and unreported-pair results establish that the remediation guarantee is broader than a literal reading of the reported-path set alone would suggest.

**Files.** `evaluation/baselines_and_ablations/mincut_vs_greedy.py`, `mincut_ablation_results_reference.json`, `tests/test_baselines_and_ablations.py`.

**Reproduce.**
```
python -m evaluation.baselines_and_ablations.mincut_vs_greedy
python -m pytest tests/test_baselines_and_ablations.py -q
```

---

## 11. Differential test against an independent policy-matching implementation

**What this is.** Not a set of individually labeled scenarios, but a large-scale statistical check on the policy-matching layer itself: 20,000 randomly generated IAM policy statements per run (repeated across four independent seeds, 80,000 total), each evaluated by this project's own evaluator and, separately, by PMapper's independently-written policy matcher (`principalmapper.querying.local_policy_simulation`), covering `Allow`/`Deny`, `Action`/`NotAction`, `Resource`/`NotResource`, exact/wildcard patterns, and the `StringEquals`/`StringLike`/`ArnEquals`/`Bool`/`Null` condition operators and their `IfExists` forms.

**Where this comes from.** PMapper is not this project's own code — it is NCC Group's independently maintained, widely-used AWS IAM analysis tool, already used elsewhere in this evaluation as a comparative baseline (category 1's related-work comparison). Using its policy matcher as a second, unrelated implementation to check agreement against is a check on correctness at the AWS-semantics level (source 3), not on any test scenario.

**Ground truth.** There is no third-party oracle here — this is a test of *agreement* between two independent implementations, not a test against a labeled answer. Disagreements are the informative signal, and every one found was individually attributed to a specific cause and checked against AWS's own documentation.

**Result.** 98.85–99.01% statement-level agreement and 97.51–97.75% policy-level agreement across four seeds. Every disagreement traced to one of three causes, each independently checked against AWS's documented behavior: PMapper matches Resource ARNs and ARN condition operators case-insensitively where AWS's own documentation specifies case-sensitive matching, and PMapper returns `false` for `StringNotLike` against an absent condition key where AWS's documentation specifies `true`. A positive control (removing the two stimuli behind these three causes) produces 100% agreement at both levels. A dedicated sensitivity test confirms the harness can detect disagreement when one is deliberately introduced.

**Files.** `evaluation/policy_semantics/differential/run_differential.py`, `POLICY_SEMANTICS_EVALUATION.md` (section 4.3).

**Reproduce.**
```
python -m evaluation.policy_semantics.differential.run_differential 20000 20260919
python -m evaluation.policy_semantics.differential.run_differential 20000 20260919 controlled
```

---

## 12. Risk-score / remediation decoupling proof

**What this is.** An empirical proof, not a labeled test set: the same four graphs from category 10 were re-scored under three different weight sets — the production weights (`irsa_bridge: 3.0, iam:PassRole: 2.5, sts:AssumeRole: 2.0, rbac_binding: 1.5, group_membership: 1.0`), a flattened set, and a set with the relative order of `irsa_bridge`/`PassRole`/`AssumeRole` deliberately inverted — and the remediation output (the set of edges the min-cut algorithm selects to cut) was compared across all three.

**Where this comes from.** This is not a technique instantiation or an external scenario — it is a direct test of an internal code property, motivated by the fact that the risk-scoring weights are hand-designed heuristics with no external validation (searched for and confirmed absent in the same methodology-and-provenance sense as the rest of this catalog: Rhino Security Labs' and Cloudsplaining's own severity documentation explicitly frame impact as depending on what is reachable, not on which mechanism was used, so no authoritative external ranking of these specific mechanisms exists to validate against).

**Ground truth.** The expected result — that remediation output is identical regardless of scoring weights — follows from code inspection of `remediation/engine.py` (every real edge is given unit capacity; `risk_score` is never referenced), then confirmed empirically rather than left as an inference from reading the code.

**Result.** Identical cut-edge sets in all four graphs, across all three weightings; only the numeric `risk_score` values attached to each path changed. A dedicated regression-sensitive test confirms this is not a vacuous pass: it rigs remediation to depend on the top-scored path on a fixture specifically constructed so the production and inverted weightings rank the two paths oppositely, and confirms the harness then correctly reports different cut sets.

**Files.** `evaluation/risk_score/decoupling_proof.py`, `decoupling_results_reference.json`, `tests/test_baselines_and_ablations.py`.

**Reproduce.**
```
python -m evaluation.risk_score.decoupling_proof
python -m pytest tests/test_baselines_and_ablations.py -q -k decoupl
```

---

## Scope and limitations

Stated plainly, in one place, for any reviewer who wants the honest boundary of what this evaluation does and does not establish:

- **Categories 1, 2, 3, 4, 6** rest on ground truth constructed and labeled by the author. This is disclosed, not hidden, in each category's own section above, and is the same methodological position every comparable tool's own evaluation takes (source 2 of the methodology section), given the absence of a shared benchmark dataset in this field.
- **Category 7/8's** 8,000-case result demonstrates internal consistency with documented AWS mechanisms and semantics at scale. It is not, and is not presented as, a claim about the real-world prevalence of any specific misconfiguration.
- **Category 9's** five real-world cases are a small, deliberately high-provenance complement, not a systematic prevalence study across many repositories.
- **Category 11's** agreement check validates the policy-matching layer against one independent implementation (PMapper). It does not constitute validation against AWS itself; no live AWS account or LocalStack policy-simulation call was used as an oracle anywhere in this evaluation.
- **Category 12** narrows, rather than eliminates, the risk-scoring heuristic's exposure: it proves the score does not affect remediation correctness, but the score itself remains an unvalidated heuristic, explicitly labeled as such, used only for display ordering.
- No category in this catalog involves a second human labeler; every author-labeled category has exactly one labeler.
