# Risk score: decoupling proof and external-anchor search

*For the case-by-case justification of the decoupling proof's fixtures, see [`../../BENCHMARK_CASE_CATALOG.md`](../../BENCHMARK_CASE_CATALOG.md), category 12.*

- `decoupling_proof.py` -- empirically proves `remediation/engine.py`'s min-cut output (the set of edges cut) is identical regardless of `scoring/risk.py`'s weights, across three weight sets including a deliberately inverted one. See section 13.1 of `evaluation/policy_semantics/POLICY_SEMANTICS_EVALUATION.md`.
- Section 13.2 of the same document records a search for an authoritative external source ranking these mechanisms by severity (none found) and the recommended downgrade framing for the paper.
- `decoupling_results_reference.json` -- the author's own run, kept as a reference.

Reproduce:
```
python -m evaluation.risk_score.decoupling_proof
python -m pytest tests/test_baselines_and_ablations.py -q -k decoupl
```
