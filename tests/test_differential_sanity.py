"""The differential harness must be able to fail: a deliberately broken evaluator must produce disagreements."""
import pytest

pytest.importorskip("principalmapper")

from evaluation.policy_semantics.differential import run_differential as rd  # noqa: E402
from ingestion import policy_eval as pe  # noqa: E402


def test_harness_detects_a_broken_evaluator(monkeypatch, tmp_path):
    baseline = rd.main(n=1500, seed=7, controlled=True, outdir=str(tmp_path))
    assert baseline["statement_level"]["disagree"] == 0

    real_match = pe._match
    monkeypatch.setattr(pe, "_match", lambda kind, c, p: (not real_match(kind, c, p)) if kind == "eq" else real_match(kind, c, p))
    broken = rd.main(n=1500, seed=7, controlled=True, outdir=str(tmp_path))
    assert broken["statement_level"]["disagree"] > 20
