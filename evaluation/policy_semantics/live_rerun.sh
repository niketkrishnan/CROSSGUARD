#!/bin/bash
# Live re-run of B10 and B11 under all three semantics. Run from the repo root
# with the venv active, Docker + Minikube running, and `awslocal` installed
# (pip install awscli-local). WARNING: benchmarks/reset_environment.sh wipes
# LocalStack (all IAM state) and restarts it.
#
#   bash evaluation/policy_semantics/live_rerun.sh
#
set -e
export AWS_DEFAULT_REGION=us-east-1 AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test
OUT=evaluation/policy_semantics/live
mkdir -p "$OUT"

run_bench () {           # $1 = b10|b11 ; rest = ServiceAccount names (== role names)
  local B=$1; shift
  echo "=== $B: reset ==="
  bash benchmarks/reset_environment.sh
  # reset_environment.sh does not know the b10/b11 ServiceAccounts
  kubectl get sa -n default -o name | grep -E "serviceaccount/(b10|b11)-" | xargs -r kubectl delete -n default
  echo "=== $B: AWS setup ==="
  bash benchmarks/bench${B#b}/setup_aws.sh
  echo "=== $B: ServiceAccounts + IRSA annotations ==="
  for sa in "$@"; do
    kubectl create serviceaccount "$sa" -n default --dry-run=client -o yaml | kubectl apply -f - >/dev/null
    kubectl annotate serviceaccount "$sa" -n default \
      "eks.amazonaws.com/role-arn=arn:aws:iam::000000000000:role/$sa" --overwrite >/dev/null
  done
  for mode in legacy annotate strict; do
    echo "=== $B: main.py --semantics $mode ==="
    python main.py --endpoint-url http://localhost:4566 --semantics "$mode" \
      --output-json "$OUT/${B}_${mode}.json" > "$OUT/${B}_${mode}.log" 2>&1 || { echo "FAILED, see $OUT/${B}_${mode}.log"; exit 1; }
  done
}

run_bench b10 b10-chain-start b10-cw-readonly b10-ddb-readonly b10-ec2-describe \
  b10-explicit-deny-admin b10-iam-readonly b10-logs-wildcard b10-mfa-gated-admin \
  b10-minimal b10-passrole-conditioned b10-passrole-scoped b10-s3-readonly b10-s3-scoped-star

run_bench b11 b11-circular-a b11-hop1 b11-nested-conditions b11-wildcard-principal-admin

python evaluation/policy_semantics/compare_live.py
