"""Tests for the real-world published-policy evaluation (RWP cases)."""
import json

from evaluation.real_world.published_policies.build_cases import all_cases
from evaluation.real_world.published_policies.policies import REAL_POLICIES
from evaluation.real_world.published_policies.run_offline import run_case


def test_all_cases_present():
    cases = all_cases()
    assert set(cases) == {f"RWP-{k}" for k in REAL_POLICIES} | {"RWP-unit42-passrole-chain"}


def test_negative_cases_have_no_admin_passrole_or_assumerole_action():
    """The four real policies must not themselves grant admin, PassRole, or
    AssumeRole -- if a future upstream policy update added one, this catches
    it rather than silently keeping a stale 'always TN' expectation."""
    for name, entry in REAL_POLICIES.items():
        actions = set()
        for stmt in entry["policy"]["Statement"]:
            a = stmt.get("Action", [])
            actions.update(a if isinstance(a, list) else [a])
        assert "*" not in actions, f"{name}: unexpectedly grants '*'"
        assert not any("passrole" in a.lower() for a in actions), f"{name}: unexpectedly grants PassRole"
        assert not any(a.lower().endswith(":assumerole") for a in actions), f"{name}: unexpectedly grants AssumeRole"


def test_offline_run_matches_declared_truth():
    for case_id, case in all_cases().items():
        paths = run_case(case)
        target = case["truth"].get("target")
        hit = [p for p in paths if p["path"][-1] == target] if target else paths
        found = bool(hit)
        assert found == case["truth"]["reachable"], f"{case_id}: expected reachable={case['truth']['reachable']}, found={found}"


def test_unit42_case_is_disclosed_as_non_verbatim():
    cases = all_cases()
    assert cases["RWP-unit42-passrole-chain"]["fully_verbatim"] is False
    for name in REAL_POLICIES:
        if REAL_POLICIES[name]["fully_verbatim"]:
            assert cases[f"RWP-{name}"]["fully_verbatim"] is True
