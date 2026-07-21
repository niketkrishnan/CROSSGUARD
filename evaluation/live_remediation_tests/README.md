# Live remediation tests

Standalone scripts that prove CrossGuard Live's remediation-apply code works against a real IAM implementation (LocalStack), independent of whether any benchmark's minimum-cut result happens to select that edge type.

## Why this exists

The benchmark suite in `../../benchmarks/` proves detection and end-to-end remediation for the paths the pathfinder actually finds and the minimum-cut algorithm actually selects. But the minimum-cut algorithm always prefers the cheapest shared bottleneck -- in every constructed benchmark (B1, B2, B6), that happens to be the `irsa_bridge` or `sts:AssumeRole` edge, never `iam:PassRole` or `group_membership`. That's correct behavior, not a gap in the benchmarks -- but it means those two remediation code paths were only unit-tested against a mock IAM client, never proven against a real IAM API.

`test_live_aws_remediation.py` closes that gap directly: it creates real IAM entities on LocalStack, calls `crossguard-live-api/app/core_adapter.py`'s `apply_aws_edge_removal()` with a hand-crafted `edge_cut` (the exact shape the remediation engine produces), and re-queries LocalStack's IAM API to confirm the change actually took effect -- including confirming that unrelated policy statements are left untouched.

## Running it

    docker ps | grep localstack || docker run -d --name localstack -p 4566:4566 localstack/localstack:4.14.0
    cd ~/projects/iam-k8s-privesc
    source venv/bin/activate
    export AWS_ACCESS_KEY_ID=test
    export AWS_SECRET_ACCESS_KEY=test
    export AWS_DEFAULT_REGION=us-east-1
    export PYTHONPATH=~/projects/iam-k8s-privesc:$PYTHONPATH
    python3 evaluation/live_remediation_tests/test_live_aws_remediation.py

The script cleans up every entity it creates, both on success and on failure, so it's safe to re-run repeatedly.

## Result (validated live against LocalStack)

    --- iam:PassRole live test ---
    BEFORE: 2 statements (PassRole + s3:GetObject) confirmed on live LocalStack
    AFTER:  PassRole statement removed, s3:GetObject statement untouched
    PASSED

    --- group_membership live test ---
    BEFORE: user confirmed a member of live-test-admin-group on live LocalStack
    AFTER:  user no longer a member of live-test-admin-group
    PASSED

    ALL LIVE TESTS PASSED

Combined with the benchmark suite's live proof of `irsa_bridge` (B1, B6) and `sts:AssumeRole` (B2) remediation, all four edge types CrossGuard's remediation engine can produce are now proven against a real IAM API, not just unit-tested against a mock client.
