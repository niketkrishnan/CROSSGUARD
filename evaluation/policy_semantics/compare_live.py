"""Compare live re-run outputs with the earlier raw results and with the offline replay."""
import json, os, sys
here = os.path.dirname(__file__)
raw = os.path.join(here, "..", "benchmarks_raw")
LEGACY_EXPECTED = {"b10": ("benchmark10_result_v2.json", 4), "b11": ("benchmark11_result.json", 3)}
ok = True
for b, (fname, n_expected) in LEGACY_EXPECTED.items():
    print(f"\n== {b} ==")
    old = json.load(open(os.path.join(raw, fname)))
    print(f"earlier raw result ({fname}): {len(old['paths'])} paths (paper: {n_expected})")
    for mode in ("legacy", "annotate", "strict"):
        p = os.path.join(here, "live", f"{b}_{mode}.json")
        if not os.path.exists(p):
            print(f"  {mode:9s} MISSING {p}"); ok = False; continue
        d = json.load(open(p))
        tiers = {"confirmed": 0, "potential": 0, "unresolved": 0}
        for x in d["paths"]:
            tiers[x.get("confidence", "confirmed")] += 1
        print(f"  {mode:9s} paths={len(d['paths'])} tiers={tiers} "
              f"exposure_findings={len(d.get('wildcard_trust_roles', []))} suppressed={len(d.get('suppressed_edges', []))}")
        reasons = {}
        for sp in d.get("suppressed_edges", []):
            key = f"{sp['type']}: {sp['reason']}"
            reasons[key] = reasons.get(key, 0) + 1
        for k, v in sorted(reasons.items()):
            print(f"      suppressed x{v}  {k}")
        for x in d["paths"]:
            print(f"      [{x.get('confidence')}] {x['start'].split(':')[-1]} -> {x['end'].split('/')[-1]}  hops={x['hops']}  irsa_trust={x.get('irsa_trust')}")
        if mode == "legacy" and len(d["paths"]) != n_expected:
            print(f"  !! legacy path count {len(d['paths'])} != {n_expected}: replay transcription or environment is off"); ok = False
print("\nLEGACY FIDELITY:", "OK" if ok else "MISMATCH -- do not use the replay tables")
sys.exit(0 if ok else 1)
