#!/bin/bash
# Scale Test 1 -- Kubernetes side. Creates 10 ServiceAccounts with IRSA
# annotations. Only sa-0 and sa-1 point at the two admin roles (genuine
# escalation paths). sa-2 through sa-9 point at random plain
# (non-admin) roles -- no escalation path, these test for false positives
# at scale.
set -e

kubectl create serviceaccount scale-sa-0 -n default
kubectl annotate serviceaccount scale-sa-0 -n default \
  eks.amazonaws.com/role-arn=arn:aws:iam::000000000000:role/scale-admin-role-A

kubectl create serviceaccount scale-sa-1 -n default
kubectl annotate serviceaccount scale-sa-1 -n default \
  eks.amazonaws.com/role-arn=arn:aws:iam::000000000000:role/scale-admin-role-B

# sa-2 through sa-9: point at plain, non-admin roles. No escalation path.
PLAIN_ROLE_INDICES=(3 17 29 41 55 63 78 91)
i=2
for role_idx in "${PLAIN_ROLE_INDICES[@]}"; do
  kubectl create serviceaccount scale-sa-$i -n default
  kubectl annotate serviceaccount scale-sa-$i -n default \
    eks.amazonaws.com/role-arn=arn:aws:iam::000000000000:role/scale-role-$role_idx
  i=$((i+1))
done

echo "Scale Test 1 K8s fixtures created: 10 ServiceAccounts (2 vulnerable, 8 safe)."
