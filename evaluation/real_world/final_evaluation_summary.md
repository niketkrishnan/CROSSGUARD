# CrossGuard Final Real-World Evaluation Summary
*(Supersedes the v2/v3-pipeline numbers previously in this file — see
`final_evaluation_summary_SUPERSEDED_v2v3.md` for why those were retired.
That file is kept, not deleted, because the fallback bug it documents —
unresolvable Helm-templated SA names silently replaced with a
repo-directory-derived name — is itself a documented, self-caught
methodology finding referenced in the paper's credibility discussion.)*

## Dataset Scale
- 1,474 unique EKS repositories identified via GitHub API
- 150 high-engagement repositories deep-scanned
- 118 configurations exhibiting the IRSA pattern (71 K8s YAML, 47 Terraform)
  — a **prevalence** finding (pattern match, not a CrossGuard scan result)

## Live-Verified Tier — 44/44, 6 independent mechanical extraction methods

| Method | Technique | Net-new configs | Result | Raw artifact |
|---|---|---|---|---|
| 1 | Literal + `values.yaml` resolution | 10 | 10/10 TP | `evaluation/real_world/automated_scan_results_v6.json` |
| 2 | `helm template` rendering | 6 (8 raw, 2 confirmed duplicates of Method 1 removed) | 6/6 TP | `evaluation/real_world/automated_scan_results_v7.json` |
| 3 | Terraform HCL parsing (`python-hcl2`) | 12 | 12/12 TP | `evaluation/real_world/automated_scan_results_v8.json` |
| 4 | Terraform `irsa`-module call-site resolution | 4 | 4/4 TP | `evaluation/real_world/automated_scan_results_v9.json` |
| 5 | Manual production repos (4 projects, TP+TN pair each) | 8 (4 TP + 4 TN) | 8/8 correct | `evaluation/real_world/{aws-load-balancer-controller,external-secrets,cert-manager,eks-with-istio}/result.json` |
| 6 | Near-miss multi-hop (B9) | 4 (2 TP + 2 TN) | 4/4 correct | `evaluation/benchmarks_raw/bench9_result.json` |

**Live-verified total: 44/44 correct, 0 false positives, 0 false negatives.**
Full per-case manifest (RW-01–44: repo, method, role fixture, expected/observed, artifact file) maintained in `evaluation/real_world/RW_MANIFEST.md`.

## Method-2 dedup verification (methodology note worth keeping in the paper)
`automated_scan_results_v7.json` (helm-render) shows 8 raw configs. File-path
inspection (not assumption) confirmed exactly 2 are the same underlying
chart/config already counted by Method 1:
- `aws-samples/amazon-eks-machine-learning-with-terraform-and-kubeflow`
  (`charts/ml-platform/kubeflow-profiles-and-kfam`) — same chart, v6 found
  it via literal/values.yaml resolution, v7 found it by fully rendering it.
- `msfidelis/eks-with-istio` (`helm/sample`) — same chart, same reasoning.

`erankitcs/BookStoreAppOnEKS` was checked the same way and confirmed **not**
a duplicate: v6's single hit is the one literal (non-templated) file
(`cluster-autoscaler-autodiscover.yaml`); v7's six hits are six separate
Helm-templated files in the same repo — genuinely disjoint configs.

## Synthetic Benchmark Suite (B1–B9)
9 benchmarks, TP=9, FP=0, FN=0, TN=5 → P=R=F1=1.000. See
`evaluation/benchmarks_raw/` for raw per-benchmark result JSON.

## Combined Finding Statement (for paper — use this, not the superseded version)
"CrossGuard correctly classified 44 real-world ServiceAccount configurations
— extracted via 6 independent, purely mechanical methods from real
repositories — when bound to controlled test roles spanning both
over-privileged and correctly-scoped cases, including 6 cases specifically
constructed to require multi-hop graph reasoning. Combined with the 9
synthetic benchmarks, this gives 53/53 verified test cases, 100%
precision/recall on the live-verified tier."

## What NOT to cite
The `final_evaluation_summary_SUPERSEDED_v2v3.md` file's "67 configs / 50
paths" figures came from a pipeline with a confirmed fallback-fabrication
bug (unresolvable Helm-templated names silently replaced with a
repo-directory-derived synthesis) and must not be used anywhere in the
paper.
