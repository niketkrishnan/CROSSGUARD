# Real-World Evaluation — RW-01–44 Case Manifest

Full per-case record of the 44-configuration live-verified real-world
evaluation tier. Every row was produced by a live, fresh re-run against
LocalStack + Minikube (not reconstructed from notes or memory) — see the
`Artifact` column for the exact JSON file backing each row.

See `evaluation/real_world/README.md` for the extraction-method
methodology and `evaluation/real_world/final_evaluation_summary.md` for
the aggregate summary this manifest supports.

**Do not cite `final_evaluation_summary_SUPERSEDED_v2v3.md`'s numbers
anywhere** — that file documents a fabrication bug in an earlier
extraction pipeline (v2/v3), kept only for the paper's own
self-caught-methodology-bug discussion.

| ID | Method | Repo / config | Role fixture | Expected | Observed | Artifact |
|---|---|---|---|---|---|---|
| RW-01 | 1 (literal + values.yaml) | awslabs/data-on-eks | over-privileged | TP | TP | `automated_scan_results_v6.json` |
| RW-02 | 1 | msfidelis/eks-with-istio (`helm/sample`, literal-resolved) | over-privileged | TP | TP | `automated_scan_results_v6.json` |
| RW-03 | 1 | aws-samples/amazon-eks-machine-learning-with-terraform-and-kubeflow (`kubeflow-profiles-and-kfam` chart) | over-privileged | TP | TP | `automated_scan_results_v6.json` |
| RW-04 | 1 | erankitcs/BookStoreAppOnEKS (`cluster-autoscaler-autodiscover.yaml`, literal) | over-privileged | TP | TP | `automated_scan_results_v6.json` |
| RW-05 | 1 | aws-samples/eks-cluster-upgrades-workshop | over-privileged | TP | TP | `automated_scan_results_v6.json` |
| RW-06 | 1 | Abhiram-Rakesh/Three-Tier-EKS-Terraform (config 1/2) | over-privileged | TP | TP | `automated_scan_results_v6.json` |
| RW-07 | 1 | Abhiram-Rakesh/Three-Tier-EKS-Terraform (config 2/2) | over-privileged | TP | TP | `automated_scan_results_v6.json` |
| RW-08 | 1 | Sarthakx67/retail-store-aws-deployment | over-privileged | TP | TP | `automated_scan_results_v6.json` |
| RW-09 | 1 | clusterfrak-dynamics/terraform-eks-addons | over-privileged | TP | TP | `automated_scan_results_v6.json` |
| RW-10 | 1 | liferaft/kubekit | over-privileged | TP | TP | `automated_scan_results_v6.json` |
| RW-11 | 2 (helm render) | erankitcs_BookStoreAppOnEKS/clients-api | over-privileged | TP | TP | `automated_scan_results_v7.json` |
| RW-12 | 2 | erankitcs_BookStoreAppOnEKS/front-end | over-privileged | TP | TP | `automated_scan_results_v7.json` |
| RW-13 | 2 | erankitcs_BookStoreAppOnEKS/infrastructure/.../appmesh-sa | over-privileged | TP | TP | `automated_scan_results_v7.json` |
| RW-14 | 2 | erankitcs_BookStoreAppOnEKS/inventory-api | over-privileged | TP | TP | `automated_scan_results_v7.json` |
| RW-15 | 2 | erankitcs_BookStoreAppOnEKS/renting-api | over-privileged | TP | TP | `automated_scan_results_v7.json` |
| RW-16 | 2 | erankitcs_BookStoreAppOnEKS/resource-api | over-privileged | TP | TP | `automated_scan_results_v7.json` |
| RW-17 | 3 (Terraform HCL) | AmanPathak-DevOps_EKS-ArgoCD-AWS-LB-Controller-Terraform | over-privileged | TP | TP | `automated_scan_results_v8.json` |
| RW-18 | 3 | Harshetjain666_terraform-aws-eks-fargate-cluster | over-privileged | TP | TP | `automated_scan_results_v8.json` |
| RW-19 | 3 | DrFaust92_terraform-kubernetes-ebs-csi-driver (`csi_rbac.tf`) | over-privileged | TP | TP | `automated_scan_results_v8.json` |
| RW-20 | 3 | mipsel64_my-cluster/efs-csi-driver | over-privileged | TP | TP | `automated_scan_results_v8.json` |
| RW-21 | 3 | yukccy_terraform-argocd-on-eks | over-privileged | TP | TP | `automated_scan_results_v8.json` |
| RW-22 | 3 | a-pavithraa_AWSEKSPOC (`k8s_externaldns_serviceaccount.tf`) | over-privileged | TP | TP | `automated_scan_results_v8.json` |
| RW-23 | 3 | a-pavithraa_AWSEKSPOC (`k8s_dynamodb_serviceaccount.tf`) | over-privileged | TP | TP | `automated_scan_results_v8.json` |
| RW-24 | 3 | AheadAviation_terraform-aws-eks-2.0 | over-privileged | TP | TP | `automated_scan_results_v8.json` |
| RW-25 | 3 | dasmeta_terraform-aws-eks (`modules/api-gw/sa.tf`) | over-privileged | TP | TP | `automated_scan_results_v8.json` |
| RW-26 | 3 | dasmeta_terraform-aws-eks (`modules/autoscaler/kube-resoures.tf`) | over-privileged | TP | TP | `automated_scan_results_v8.json` |
| RW-27 | 3 | adavarski_AWS-EKS-Terraform (`helm/lb_ingress_controller`) | over-privileged | TP | TP | `automated_scan_results_v8.json` |
| RW-28 | 3 | aws-samples_.../kagent/main.tf (`kagent-sa`, distinct config from RW-03, same repo) | over-privileged | TP | TP | `automated_scan_results_v8.json` |
| RW-29 | 4 (module call-site) | squareops_.../aws-ebs-csi-driver (`ebs-csi-controller-sa`) | over-privileged | TP | TP | `automated_scan_results_v9.json` |
| RW-30 | 4 | squareops_.../prometheus (`amp-ingest`) | over-privileged | TP | TP | `automated_scan_results_v9.json` |
| RW-31 | 4 | squareops_.../prometheus (`amp-query`) | over-privileged | TP | TP | `automated_scan_results_v9.json` |
| RW-32 | 4 | squareops_.../aws-vpc-cni (`aws-node`) | over-privileged | TP | TP | `automated_scan_results_v9.json` |
| RW-33 | 5 (manual production repos) | aws-load-balancer-controller | `AdministratorAccess` | TP | TP | `evaluation/real_world/aws-load-balancer-controller/result.json` |
| RW-34 | 5 | aws-load-balancer-controller-safe | ELB read-only (scoped) | TN | TN | same file |
| RW-35 | 5 | external-secrets | `AdministratorAccess` | TP | TP | `evaluation/real_world/external-secrets/result_fresh.json` |
| RW-36 | 5 | external-secrets-scoped | scoped to `myapp/*` secrets | TN | TN | same file |
| RW-37 | 5 | cert-manager | `AdministratorAccess` | TP | TP | `evaluation/real_world/cert-manager/result_fresh.json` |
| RW-38 | 5 | cert-manager-scoped | Route53 DNS01 only | TN | TN | same file |
| RW-39 | 5 | eks-with-istio `sample-app` → `eks-istio-karpenter` (same source repo as RW-02, different real component) | `AdministratorAccess` | TP | TP | `evaluation/real_world/eks-with-istio/result_fresh.json` |
| RW-40 | 5 | eks-with-istio `sample-app-scoped` → `eks-istio-app-scoped` | S3 app bucket only | TN | TN | same file |
| RW-41 | 6 (B9 near-miss) | b9-cluster-autoscaler → b9-autoscaler-admin | partial-privilege, 2-hop bare PassRole | TP | TP (Conservative-Potential — see `evaluation/passrole_classification/`) | `evaluation/benchmarks_raw/bench9_result.json` |
| RW-42 | 6 | b9-efs-csi-controller-sa → b9-efs-node-role | correctly-scoped | TN | TN | same |
| RW-43 | 6 | b9-aws-node → b9-autoscaler-admin (3-hop via b9-shared-jump-role) | partial-privilege | TP | TP (Conservative-Potential) | same |
| RW-44 | 6 | b9-amp-ingest → b9-amp-ingest-role | correctly-scoped | TN | TN | same |

**Total: 44/44, 0 false positives, 0 false negatives.**

## Notes on same-repo, multiple-config entries

Several repos legitimately contribute more than one manifest row because
they define more than one distinct ServiceAccount/role pairing:

- `erankitcs/BookStoreAppOnEKS` — RW-04 (one literal, non-templated YAML
  file) is disjoint from RW-11–16 (six separate Helm-templated files,
  rendered via `helm template`). Verified by direct file inspection, not
  assumed.
- `aws-samples/amazon-eks-machine-learning-with-terraform-and-kubeflow` —
  RW-03 (Helm chart SA) and RW-28 (`kagent-sa`, defined directly in
  Terraform HCL) are two distinct configs in the same repo.
- `msfidelis/eks-with-istio` — RW-02 (automated extraction of the
  `helm/sample` chart's default SA) and RW-39 (manual test of a
  different real component in the same repo, `iam_karpenter.tf`'s
  Karpenter role) are two distinct configs, confirmed via file inspection.

## Confirmed duplicates (excluded from the count above)

Method 2's raw output was 8 configs; 2 were confirmed (via file-path
inspection, not assumption) to be the same underlying chart already
counted under Method 1, and are excluded from RW-11–16 above:
- `aws-samples/.../kubeflow-profiles-and-kfam` (same chart as RW-03)
- `msfidelis/eks-with-istio/helm/sample` (same chart as RW-02)
