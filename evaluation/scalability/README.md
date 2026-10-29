# Scalability Sweep

`scale_sweep_trial.py` builds one synthetic graph of a given size (matching
the real graph schema: node `type` starting with `k8s`/`aws`, `is_admin`
flag) and times ONE call to the real `pathfinder.search.find_all_cross_layer_paths`
against it. Invoked as a fresh subprocess per (size, trial) for true OS-level
process isolation -- sequential in-process measurement produced a
non-monotonic artifact in an earlier run (10K nodes appearing slower than
15K/20K), traced to resource contention, not the algorithm.

`scale_sweep_results_fresh.csv`: 11 sizes (48-25,000 nodes), 5 trials each
(3 at 25,000 for runtime practicality). Columns: nodes,edges,trial,paths_found,seconds.

Regression on this data: exponent ~= n^2.01, R^2 ~= 0.985 -- confirms the
quadratic-scaling finding (root cause: entry-point x admin-node pair
checking is O(n^2), since both populations grow linearly with graph size).

NOTE: an earlier scale-sweep run (script + CSV) that produced different
absolute numbers (e.g. ~27.6s at 25K nodes vs. this run's ~99s) was run in
a prior session and its raw files were lost (a `.lnk` Recent-files trace is
all that remained). That prior synthetic-graph generator is not recoverable
and its exact node/edge density is unknown, so its numbers are NOT
comparable to this file's and should not be spliced together. THIS file's
numbers are the current source of truth for Table VII -- fully reproducible
by re-running scale_sweep_trial.py.
