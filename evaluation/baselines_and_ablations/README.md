# Baselines and ablations

*For the case-by-case justification of these ablation graphs, see [`../../BENCHMARK_CASE_CATALOG.md`](../../BENCHMARK_CASE_CATALOG.md), category 10.*

- `naive_baseline.py` / `run_naive_baseline.py` -- the simplest possible detector (IRSA annotation next to an admin-labeled role, nothing else), run against the same case sets used to evaluate CrossGuard. See section 12.1 of `evaluation/policy_semantics/POLICY_SEMANTICS_EVALUATION.md`.
- `mincut_vs_greedy.py` -- four constructed-graph ablations of `remediation/engine.py`'s min-cut (greedy comparison, alternate-route, unreported-pair, disjoint-chains sanity check). Section 12.2.
- `EXTERNAL_TOOL_ATTEMPTS.md` -- what was tried with IAM-Deescalate and IAMPERE as additional baselines, and why neither was run to completion here. Section 12.3.
- `*_results_reference.json` -- the author's own run, kept as a reference to diff a re-run against.

Reproduce:
```
python -m evaluation.baselines_and_ablations.run_naive_baseline
python -m evaluation.baselines_and_ablations.mincut_vs_greedy
python -m pytest tests/test_baselines_and_ablations.py -q
```
