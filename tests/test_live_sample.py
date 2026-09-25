"""namespace_case must make role names unique across cases and keep the
sa_role_map / truth target pointing at the renamed roles."""
import json

from evaluation.generated_benchmark.generator import generate, to_jsonl
from evaluation.generated_benchmark.live_sample import namespace_case


def test_namespace_case_produces_valid_unique_names(tmp_path):
    cases = generate(60, seed=11, split="dev")
    seen = set()
    for c in cases:
        raw = json.loads(json.dumps({
            "case_id": c.case_id, "category": c.category, "recipe": c.recipe,
            "entry_sa": c.entry_sa, "entry_ns": c.entry_ns, "roles": c.roles,
            "sa_role_map": c.sa_role_map, "truth": c.truth,
        }))
        ns = namespace_case(raw)
        names = [r["RoleName"] for r in ns["roles"]]
        assert len(names) == len(set(names)), f"dup within case {c.case_id}"
        for n in names:
            assert len(n) <= 64
            assert n not in seen, f"collision across cases on {n}"
        seen.update(names)
        # every sa_role_map value must exist among the renamed roles
        for role_name in ns["sa_role_map"].values():
            assert role_name in names
        if raw["truth"].get("target"):
            arns = {r["Arn"] for r in ns["roles"]}
            assert ns["truth"]["target"] in arns


def test_live_sample_script_resets_before_every_case(tmp_path, capsys):
    """Regression test for the cross-case contamination bug: the emitted
    script must reset LocalStack before EACH case, not once at the top,
    or an earlier case's roles/paths leak into a later case's result."""
    import sys
    from evaluation.generated_benchmark import live_sample

    cases = generate(30, seed=13, split="dev")
    to_jsonl(cases, tmp_path / "dev_cases.jsonl")
    live_sample.__file__ = str(tmp_path / "live_sample.py")  # so `here` resolves under tmp_path
    old_argv = sys.argv
    sys.argv = ["live_sample.py", "--split", "dev", "--per-recipe", "1"]
    try:
        live_sample.main()
    finally:
        sys.argv = old_argv
    out = capsys.readouterr().out
    n_headers = len([l for l in out.splitlines()
                    if l.startswith('echo "===') and "live sample complete" not in l])
    n_resets = out.count("reset_environment.sh")
    n_checks = out.count("python -m evaluation.generated_benchmark.check_live_case")
    assert n_headers > 0
    assert n_resets == n_headers, "one reset must precede every case, not just the first"
    assert n_checks == n_headers
    assert "k8s:sa:" in out, "check_live_case must be given the entry SA's graph node id"
    assert "rm -f evaluation/generated_benchmark/live/summary.jsonl" in out, \
        "summary.jsonl (append-only) must be cleared at the start of every run, or old runs' results leak in"


def test_namespace_case_preserves_glob_resource_matching():
    """Regression test: a PassRole Resource glob sharing only a name PREFIX
    with its target (e.g. "role/app-12345-*" vs role "app-12345-admin")
    must still match after namespacing, or the live-sample script silently
    breaks passrole_glob_resource-style cases."""
    import fnmatch

    from evaluation.generated_benchmark.generator import generate

    cases = [c for c in generate(300, seed=21, split="dev") if c.recipe == "passrole_glob_resource"]
    assert cases, "no passrole_glob_resource cases generated for this seed/n"
    for c in cases[:5]:
        raw = json.loads(json.dumps({
            "case_id": c.case_id, "category": c.category, "recipe": c.recipe,
            "entry_sa": c.entry_sa, "entry_ns": c.entry_ns, "roles": c.roles,
            "sa_role_map": c.sa_role_map, "truth": c.truth,
        }))
        ns = namespace_case(raw)
        entry = next(r for r in ns["roles"] if "entry" in r["RoleName"])
        glob = entry["policy_documents"][0]["Statement"][0]["Resource"]
        target_role = next(r for r in ns["roles"] if r["Arn"] == ns["truth"]["target"])
        assert fnmatch.fnmatchcase(target_role["Arn"], glob), \
            f"{c.case_id}: renamed glob {glob!r} no longer matches renamed target {target_role['Arn']!r}"
