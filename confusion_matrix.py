"""
confusion_matrix.py -- Section 1.2 (Confusion Matrix Data)

Run each benchmark for real (main.py --output-json), then run this
script pointing at the resulting JSON files. It compares CrossGuard's
reported paths against the documented ground truth for B1-B7 and
computes TP/FP/FN/TN, Precision, Recall, F1.

Usage (on your WSL box, after a fresh reset_environment.sh + running
each benchmark's setup_aws.sh / kubectl apply + main.py --output-json):

    python3 confusion_matrix.py \
        --b1 benchmark1_result.json --b2 benchmark2_result.json \
        --b3 benchmark3_result.json --b4 benchmark4_result.json \
        --b5 benchmark5_result.json --b6 benchmark6_result.json \
        --b7 benchmark7_result.json

Ground truth encodes what a CORRECT tool should report, per your own
benchmark READMEs:
    B1: 1 cross-layer path expected
    B2: 1 cross-layer path expected
    B3: 1 cross-layer path expected (4 other SAs must NOT produce paths)
    B4: 0 cross-layer paths expected (same-layer only, by design)
    B5: 0 cross-layer paths expected (false-positive control)
    B6: 2 cross-layer paths expected (shared bottleneck)
    B7: 0 cross-layer paths expected (not a privesc scenario)

TP = a genuinely-exploitable cross-layer path that ground truth says
     should exist, and the tool reported it.
FP = the tool reported a cross-layer path where ground truth says none
     should exist (or reported MORE than ground truth's count).
FN = ground truth says a path should exist but the tool reported fewer
     than expected.
TN = ground truth says 0 paths, and the tool reported 0 paths.
"""

from __future__ import annotations
import argparse
import json

GROUND_TRUTH = {
    "b1": 1, "b2": 1, "b3": 1, "b4": 0, "b5": 0, "b6": 2, "b7": 0,
}


def load(path):
    if not path:
        return None
    with open(path) as f:
        return json.load(f)


def main():
    ap = argparse.ArgumentParser()
    for b in GROUND_TRUTH:
        ap.add_argument(f"--{b}", default=None, help=f"path to {b} --output-json result")
    args = ap.parse_args()

    tp = fp = fn = tn = 0
    rows = []

    for b, expected in GROUND_TRUTH.items():
        path = getattr(args, b)
        data = load(path)
        if data is None:
            print(f"[skip] {b}: no file provided")
            continue

        found = len(data.get("paths", []))

        if expected == 0:
            if found == 0:
                tn += 1
                verdict = "TN"
            else:
                fp += found  # each unexpected path is a false positive
                verdict = f"FP x{found}"
        else:
            if found >= expected:
                tp += expected
                if found > expected:
                    fp += (found - expected)
                    verdict = f"TP x{expected} + FP x{found - expected}"
                else:
                    verdict = f"TP x{expected}"
            else:
                tp += found
                fn += (expected - found)
                verdict = f"TP x{found} + FN x{expected - found}"

        rows.append((b.upper(), expected, found, verdict))

    print(f"\n{'Bench':<6}{'Expected':<10}{'Found':<8}{'Verdict'}")
    for r in rows:
        print(f"{r[0]:<6}{r[1]:<10}{r[2]:<8}{r[3]}")

    print(f"\nTP={tp}  FP={fp}  FN={fn}  TN={tn}")

    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else float("nan")

    print(f"Precision = {precision:.3f}" if precision == precision else "Precision = N/A")
    print(f"Recall    = {recall:.3f}" if recall == recall else "Recall = N/A")
    print(f"F1        = {f1:.3f}" if f1 == f1 else "F1 = N/A")


if __name__ == "__main__":
    main()
