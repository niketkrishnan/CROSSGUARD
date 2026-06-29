# PMapper Comparison Results

## Setup
PMapper (principalmapper) v1.x, installed via pip, patched for two
Python 3.12 compatibility issues (collections.Mapping moved to
collections.abc; LocalStack's get_account_authorization_details omits
PolicyName for some managed policies -- both are environment/dependency
compatibility fixes, not changes to PMapper's actual analysis logic).
Run against the same LocalStack instance used for our tool's benchmarks.

## Benchmark 1 (direct IRSA, 1 hop)

PMapper graph: 2 nodes (1 admin), 0 edges.
PMapper privesc query output:
  role/admin-role is an administrative principal

PMapper found ZERO escalation paths. It correctly identifies admin-role
as an admin, but cannot see vulnerable-sa, the IRSA annotation, or any
way to reach admin-role at all -- its trust policy principal is an AWS
service (ec2.amazonaws.com), which doesn't map to any IAM principal
PMapper tracks as having access.

Our tool: 1 path found, vulnerable-sa --[irsa_bridge]--> admin-role,
risk score 6.0, with remediation command.

## Benchmark 2 (multi-hop chain, 3 hops)

PMapper graph: 5 nodes (2 admins), 2 edges.
PMapper privesc query output:
  role/admin-role is an administrative principal
  role/b2-admin-role is an administrative principal
  role/b2-role-b can escalate privileges by accessing the administrative
    principal role/b2-admin-role:
     role/b2-role-b can access via sts:AssumeRole role/b2-admin-role
  role/b2-role-a can escalate privileges by accessing the administrative
    principal role/b2-admin-role:
     role/b2-role-a can access via sts:AssumeRole role/b2-role-b
     role/b2-role-b can access via sts:AssumeRole role/b2-admin-role

PMapper correctly identifies the AWS-only sub-chain
(b2-role-a -> b2-role-b -> b2-admin-role), since this is entirely
within its domain. However, it cannot answer the question that actually
matters for risk: WHO can become b2-role-a in the first place? It has
no concept of bench2-sa, the IRSA annotation, or a Kubernetes pod as an
attacker entry point. Its output describes a hypothetical
("if you already control b2-role-a, here's how you'd escalate further")
rather than an actual attacker-reachable path.

Our tool: 1 complete path found, starting from the real entry point:
bench2-sa --[irsa_bridge]--> b2-role-a --[iam:PassRole]--> b2-role-b
--[sts:AssumeRole]--> b2-admin-role, risk score 5.0, with remediation.

## Summary

| Benchmark | PMapper finds | Our tool finds |
|---|---|---|
| B1 | 0 paths (admin-role is unreachable to it) | 1 path, full attacker-reachable chain |
| B2 | Partial AWS-only sub-chain, no real entry point | 1 path, full attacker-reachable chain incl. K8s entry point |
| B3 | 0 paths (no K8s awareness at all) | 1 path, correctly isolates 1-of-5 vulnerable SA |
| B4 | Would find this (same-layer, AWS only) | Found (parity case, by design) |
| B5 | 0 paths (correct, but for the wrong reason -- no visibility at all, not correct analysis) | 0 paths (correct, because it analyzed the role and found no escalation) |
| B6 | Partial AWS-only sub-chains (same limitation as B2) | 2 paths, correctly ranked by hop count |
| B7 | N/A (no Kubernetes RBAC concept exists in PMapper) | Correctly resolves cross-namespace RBAC binding |

The core finding: PMapper is not simply "blind" -- it can correctly
analyze whatever portion of an attack chain is entirely within AWS IAM.
Its fundamental limitation is that it cannot identify the actual
attacker-reachable entry point when that entry point is a compromised
Kubernetes identity, because it has no model of Kubernetes RBAC or IRSA
at all. This is precisely the gap this tool's C1/C2 contributions close.
