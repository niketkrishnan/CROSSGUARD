# Environment for the benchmark scripts.
# Usage (from the repository root): source benchmarks/common.sh

export PATH="$PATH:$HOME/bin"
export AWS_DEFAULT_REGION=us-east-1 AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test

# Removes ServiceAccounts that reset_environment.sh does not know about (B8 to B11).
# Run it after every reset: ./benchmarks/reset_environment.sh && cleanx
cleanx() {
  kubectl delete serviceaccount bench8-sa-1 bench8-sa-2 b9-amp-ingest -n default --ignore-not-found
  kubectl delete serviceaccount b9-aws-node b9-cluster-autoscaler b9-efs-csi-controller-sa -n kube-system --ignore-not-found
  kubectl get sa -n default -o name | grep -E "serviceaccount/(b10|b11)-" | xargs -r kubectl delete -n default
}

for t in privesc-scan awslocal kubectl docker; do
  command -v "$t" >/dev/null 2>&1 || echo "MISSING: $t (privesc-scan: run 'source venv/bin/activate'; others: see the Requirements section of the main README)"
done
