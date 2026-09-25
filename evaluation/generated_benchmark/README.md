# Generated benchmark

*For the case-by-case justification of these 21 recipes (what each targets and why), see [`../../BENCHMARK_CASE_CATALOG.md`](../../BENCHMARK_CASE_CATALOG.md), category 7/8.*

Large, labelled benchmark of synthetic AWS IAM + Kubernetes RBAC graphs,
addressing the fact that B1-B11 (9-15 cases) were hand-labelled by the
tool's own authors. Every case is generated from a fixed recipe with a
declared, mechanically-derived truth label; see `generator.py`'s module
docstring for the four case categories and `oracle.py`'s for how the label
is independently re-checked. `*_cases.jsonl` are not committed (9+ MB,
fully reproducible) -- regenerate them:

```
python -m evaluation.generated_benchmark.generator --n 4000 --seed 30001 --split dev      --out evaluation/generated_benchmark/dev_cases.jsonl
python -m evaluation.generated_benchmark.generator --n 4000 --seed 77777 --split heldout  --out evaluation/generated_benchmark/heldout_cases.jsonl
python -m evaluation.generated_benchmark.run_benchmark --split dev
python -m evaluation.generated_benchmark.run_benchmark --split heldout
```

`dev_results_reference.json` / `heldout_results_reference.json` are the
author's own run, kept as a reference to diff your run against (should be
byte-identical given the fixed seeds and no code changes).

For a live LocalStack + Minikube sample (2 cases per recipe, ~40 total):

```
python -m evaluation.generated_benchmark.live_sample --split dev --per-recipe 2 > /tmp/live_sample.sh
bash /tmp/live_sample.sh
cat evaluation/generated_benchmark/live/summary.json
```
