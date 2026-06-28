#!/bin/bash
# Full reset: wipes LocalStack (loses all IAM state) and deletes all
# benchmark-created Kubernetes resources, so each benchmark can be run
# against a clean environment for official evaluation results.
set -e

echo "Stopping and removing LocalStack container..."
docker rm -f localstack 2>/dev/null || true

echo "Starting fresh LocalStack..."
docker run -d --name localstack -p 4566:4566 localstack/localstack:4.14.0
sleep 15

echo "Deleting benchmark-created K8s resources (pods + service accounts)..."
kubectl delete pod --all -n default --ignore-not-found
kubectl delete serviceaccount vulnerable-sa bench2-sa bench3-sa-0 bench3-sa-1 bench3-sa-2 bench3-sa-3 bench3-sa-4 bench4-sa bench5-sa -n default --ignore-not-found

echo "Environment reset complete. Run a single benchmark's setup_aws.sh + kubectl commands next."
