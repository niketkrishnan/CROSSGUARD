# Scale Test 2 -- Deep Chain (10 hops)

## Purpose
Verify BFS correctly finds long escalation chains without truncation,
timeout, or silently stopping early.

## Fixture
deep-chain-sa --IRSA--> deep-role-1 --PassRole--> deep-role-2 --PassRole--> ...
--PassRole--> deep-role-10 (AdministratorAccess)

10 roles, each role 1-9 holds iam:PassRole permission scoped specifically
to the next role in the chain.

## Setup
1. ./benchmarks/reset_environment.sh
2. python3 benchmarks/scale_test_2/generate_deep_chain.py
3. kubectl create serviceaccount deep-chain-sa -n default
4. kubectl annotate serviceaccount deep-chain-sa -n default eks.amazonaws.com/role-arn=arn:aws:iam::000000000000:role/deep-role-1
5. python3 benchmarks/scale_test_2/run_scale_test.py

## Results (5 runs, validated live against LocalStack + Minikube)

Resulting graph: 136 nodes, 61 edges.

| Metric | Mean | Std Dev |
|---|---|---|
| Wall-clock time | 1.04s | 0.052s |
| Peak memory | 10.6MB | 0.35MB |

Hops found: [10, 10, 10, 10, 10] across all 5 runs -- the full 10-hop
chain was correctly traced every time, with the correct remediation
(minimum cut on a simple chain correctly identifies any single edge --
here, the final iam:PassRole edge into deep-role-10).

## Note on where time is actually spent

This test is notably FASTER than Scale Test 1 (1.04s vs 6.16s mean)
despite having a deeper chain, because Scale Test 1's larger entity
count (50 users + 100 roles vs 10 roles here) means significantly more
sequential boto3 API calls during ingestion (Module 1). This indicates
the tool's runtime is currently dominated by AWS API round-trip latency
during ingestion, not by graph algorithm complexity (BFS itself is
effectively instantaneous even at depth 10). This is a useful
distinction for any future performance optimization work: parallelizing
the ingestion API calls (currently sequential) would likely yield far
more speedup than optimizing the graph algorithms themselves.
