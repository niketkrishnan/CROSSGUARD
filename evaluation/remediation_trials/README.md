# Remediation Trials -- Raw Per-Trial Data

40 trials total, 4 fix types x 10 trials each, fresh environment reset
before each trial.

- `b1_trial{1-3}_{before,after}.json`: irsa_bridge (B1). NOTE: only 3 of
  the 10 original trials' raw JSON survived from the original session;
  the remaining 7 were re-run fresh in a later session -- see
  `irsa_bridge_10trial_rerun.txt` for that batch's raw console output
  (mean=0.147s, stdev=0.023s, measuring ONLY the `kubectl annotate ...-`
  removal command latency -- NOT necessarily the same operation the
  original, unrecovered 0.299s figure measured; treat these as two
  possibly-different measurement definitions, not a contradiction to
  silently resolve).
- `b2_trial{1-3}_{before,after}.json`: sts:AssumeRole (B2). Mean 0.592s,
  stdev 0.021s across the real 10-trial batch (raw values in the prior
  session transcript, not saved as individual files beyond trials 1-3).
- `b8_trial{1-3}_{before,after}.json`: iam:PassRole (B8). Mean 0.820s
  (0.621s excluding 1 outlier trial, 2.61s vs ~0.6s for the other 9).
- `b6_confirm_{before,after}.json`: shared-bottleneck confirmation (B6) --
  2 paths -> 1 fix -> 0 paths, 0.132s.
- group_membership (B4): raw trial JSON files not saved individually;
  10-trial batch mean 0.595s, stdev 0.008s, per-trial values in the prior
  session transcript.
