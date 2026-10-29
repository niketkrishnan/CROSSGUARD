# Evaluation Directory — Index

This directory contains the complete evidence trail for every claim in
the paper. Start here if you're a reviewer, a collaborator, or an AI
assistant picking up this project without prior context.

**For "how many test cases, what are they, and why" — read
[`../BENCHMARK_CASE_CATALOG.md`](../BENCHMARK_CASE_CATALOG.md) first.**
It is the single authoritative accounting of every benchmark case across
this entire evaluation (12 categories, methodology and provenance for
each, exact reproduction commands), and is the document to point a
reviewer at for any question of that form.

For the full evaluation narrative — what was implemented, the live
verification results, and every finding — read
[`policy_semantics/POLICY_SEMANTICS_EVALUATION.md`](policy_semantics/POLICY_SEMANTICS_EVALUATION.md)
and `evaluation_complete_final.md` (repo root). Everything in this
directory is the raw evidence those documents summarize and cite.

## Directory map

| Path | Contents |
|---|---|
| `benchmarks_raw/` | Raw result JSON for benchmarks B1–B11 (`benchmarkN_result.json`), plus BishopFox/Kubernetes Goat results |
| `cloudsplaining_baseline/` | Cloudsplaining baseline run against each benchmark's LocalStack IAM state (auth-details input + findings/report/results output per benchmark) |
| `live_remediation_tests/` | Automated test script for live-AWS remediation verification |
| `passrole_classification/` | `classify_passrole_paths.py` — the Confirmed vs. Conservative-Potential classifier — plus every fresh classification run's output. **Read this before citing any PassRole-dependent path as a clean true positive.** |
| `real_world/` | The 44-configuration live-verified real-world evaluation. See `real_world/README.md` for methodology, `RW_MANIFEST.md` for the full per-case table, `final_evaluation_summary.md` for the current summary (⚠ do NOT cite `final_evaluation_summary_SUPERSEDED_v2v3.md`'s numbers — see that file's own header) |
| `real_world/published_policies/` | Five real-world cases built from verbatim, currently-published IAM policies of widely-deployed EKS add-ons, plus one case sourced to a Unit 42 report. Offline and live-verified, 5/5. |
| `policy_semantics/` | The policy evaluator (Deny precedence, Condition evaluation, IRSA trust checking, PassRole pairing, wildcard trust) and its full verification record: live re-runs of B10/B11, and a differential test against PMapper's independent policy matcher. `POLICY_SEMANTICS_EVALUATION.md` is the narrative writeup. |
| `generated_benchmark/` | The 8,000-case generated benchmark (4,000 development + 4,000 held-out), 21 recipes, an independent oracle, and a 42-case live LocalStack/Minikube sample. |
| `baselines_and_ablations/` | A naive-detector baseline comparison, four min-cut ablations, and a record of attempts to run IAM-Deescalate and IAMPERE as additional baselines. |
| `risk_score/` | Empirical proof that remediation output is independent of the risk-scoring heuristic's weights, plus a documented search for (and absence of) an external severity ranking to validate those weights against. |
| `remediation_trials/` | Raw per-trial JSON for all 40 remediation trials (4 fix types × 10 trials), with a README noting which trials have fully recovered raw data vs. transcript-only values |
| `scalability/` | `scale_sweep_trial.py` (synthetic graph generator + real pathfinder timing) and `scale_sweep_results_fresh.csv` (11 sizes × 5 trials, raw). This is the CURRENT scalability data — an earlier sweep's raw files were lost and are not recoverable; do not cite old scalability numbers from anywhere outside this folder. |
| `bishopfox_evaluation.md`, `bishopfox_result.json` | BishopFox IAM-Vulnerable test environment results |
| `eks_goat_assessment.md` | Why OWASP EKS Goat is correctly out of scope (no IRSA annotations anywhere in its manifests) |
| `kubernetes_goat_evaluation.md`, `kubernetes_goat_result.json` | Kubernetes Goat compounding-misconfiguration test |
| `pmapper_comparison.md` | PMapper baseline methodology and per-benchmark comparison |
| `remediation_verification.md` | Remediation correctness verification notes |

## Quick facts (see `evaluation_complete_final.md` for full detail + sources)

- **Confusion matrix**: TP=9, FP=0, FN=0, TN=5 (synthetic benchmarks B1–B9)
- **Real-world live-verified**: 44/44 correct, 0 FP, 0 FN, 6 independent extraction methods
- **Scalability**: empirical exponent about 2.01, R² > 0.98 (current data, `scalability/`)
- **Remediation**: 40/40 trials successful across 4 fix types
- **PassRole classification**: of 12 tested PassRole-relevant paths, 5 Confirmed (AssumeRole-backed), 7 Conservative-Potential (bare PassRole grant, no independently-modeled completing action)
- **Known limitation**: policy Condition evaluation (explicit Deny, MFA) not modeled — 3 documented false positives in B10, root cause confirmed
- **Known limitation**: wildcard trust (`Principal: "AWS": "*"`) not modeled as a graph edge — confirmed directly in `graph/builder.py`; B11's wildcard "TP" is via IRSA binding only, not wildcard-trust reasoning

## Reproducibility

- Python 3.12.3, LocalStack 4.14.0, Minikube v1.38.1
- Pinned dependency versions: see `evaluation_complete_final.md` Section 15
- PMapper = PyPI package `principalmapper` v1.1.5 (not "pmapper" — that's the CLI command name)
- Cloudsplaining v0.9.1
- Every evaluation command used `--endpoint-url http://localhost:4566` (LocalStack) and local Minikube — no real AWS resources were ever touched
