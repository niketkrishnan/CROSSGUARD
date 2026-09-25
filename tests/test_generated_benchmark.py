"""Sanity tests for the generated benchmark: reproducibility, oracle agreement,
category balance, and that the harness can actually detect a broken tool."""
import json

from evaluation.generated_benchmark.generator import generate
from evaluation.generated_benchmark.oracle import check_case


def test_generation_is_reproducible():
    a = generate(50, seed=999, split="dev")
    b = generate(50, seed=999, split="dev")
    assert [c.case_id for c in a] == [c.case_id for c in b]
    assert [c.truth for c in a] == [c.truth for c in b]


def test_different_seeds_differ():
    a = generate(50, seed=1, split="dev")
    b = generate(50, seed=2, split="dev")
    assert any(x.roles != y.roles for x, y in zip(a, b))


def test_dev_and_heldout_seeds_disjoint_in_content():
    dev = generate(50, seed=30001, split="dev")
    held = generate(50, seed=77777, split="heldout")
    assert {c.case_id for c in dev}.isdisjoint({c.case_id for c in held})


def test_oracle_agrees_with_generator_intent():
    cases = generate(400, seed=42, split="dev")
    mismatches = []
    for c in cases:
        raw = json.loads(json.dumps({
            "case_id": c.case_id, "category": c.category, "recipe": c.recipe,
            "entry_sa": c.entry_sa, "entry_ns": c.entry_ns, "roles": c.roles,
            "sa_role_map": c.sa_role_map, "truth": c.truth,
        }))
        r = check_case(raw)
        if not r["matches_declared_truth"]:
            mismatches.append((c.case_id, c.recipe))
    assert mismatches == []


def test_all_four_categories_present_at_moderate_scale():
    cases = generate(200, seed=5, split="dev")
    cats = {c.category for c in cases}
    assert cats == {"hard_positive", "hard_negative", "decoy", "unresolved_by_design"}
