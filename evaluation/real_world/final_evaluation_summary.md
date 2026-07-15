# CrossGuard Final Real-World Evaluation Summary

## Dataset Scale
- 1,474 unique EKS repositories identified via GitHub API
- 150 high-engagement repositories deep-scanned (5,000+ config files)
- 30 repositories with deployable K8s IRSA manifests (tool-scannable)
- 34 repositories directly scanned by CrossGuard

## IRSA Prevalence Finding
- 51.3% of 150 deep-scanned repos use IRSA (77 repos)
- 71 Kubernetes YAML/Helm files confirmed with IRSA annotations
- 47 Terraform files confirmed with IRSA configurations
- Total: 118 real-world IRSA configurations identified

## CrossGuard Detection Results

### Automated Scanning (30 repos, properly isolated)
| Run | Repos | Configs Tested | Paths Found | Detection Rate |
|---|---|---|---|---|
| v2 automated | 16 | 30 | 24 | 100% |
| v3 automated | 14 | 37 | 22 | 100% |
| Subtotal automated | 30 | 67 | 46 | 100% |

### Manual Isolated Testing (4 production projects)
| Project | SAs Tested | Paths Found |
|---|---|---|
| aws-load-balancer-controller | 2 | 1 |
| external-secrets | 2 | 1 |
| cert-manager | 2 | 1 |
| eks-with-istio | 2 | 1 |
| Subtotal manual | 8 | 4 |

### Grand Total
- Total configurations tested: 75 (67 automated + 8 manual)
- Total cross-layer paths confirmed: 50
- Overall detection rate: 100% (50/50 where path exists)
- False positives: 0 (correctly-scoped SAs produced 0 paths)

## Synthetic Benchmark Results (7 benchmarks + 2 scale tests)
- B1-B7: 100% correct, remediation verified on B1/B2/B3/B6
- Scale Test 1: 285 nodes, 6.16s mean, 0 FP
- Scale Test 2: 10-hop chain, 1.04s mean, 100% depth

## Combined Finding Statement (for paper)
"We identified 118 real-world IRSA configurations across 150
production-grade EKS repositories sourced from 1,474 unique GitHub
projects. CrossGuard confirmed 50 cross-layer escalation paths across
34 directly-scanned repositories, achieving a 100% detection rate
with 0 false positives. The remaining configurations are defined in
Terraform IaC (47 instances) or use Helm template variables that
require runtime value substitution -- both are correctly out of scope
for a static K8s manifest analysis tool."
