# Real-World Test: cert-manager

## Source
github.com/cert-manager/cert-manager
The most widely deployed certificate management controller for Kubernetes.
Uses IRSA when integrated with Route53 for DNS01 ACME challenges.

## What we tested
Scenario 1 (MISCONFIGURED): cert-manager SA with AdministratorAccess
Scenario 2 (CORRECT): cert-manager-scoped SA with Route53 DNS01 only

## Result
Paths found: 1 (Scenario 1 only)
Path: cert-manager --[irsa_bridge]--> cert-manager (admin)
Risk score: 6.0
False positives: 0
Remediation: kubectl annotate serviceaccount cert-manager -n cert-manager eks.amazonaws.com/role-arn-
