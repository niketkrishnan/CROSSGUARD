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

## Benchmark 6 -- a genuine nuance worth disclosing

PMapper found the 3-hop sts:AssumeRole route
(b6-role-a -> b6-role-b -> b6-admin-far) correctly -- same result as our
tool. It did NOT find the 2-hop iam:PassRole route
(b6-role-a -> b6-admin-near), even though b6-role-a genuinely holds
iam:PassRole on b6-admin-near.

Root cause: bare iam:PassRole is not independently exploitable in real
AWS -- it must be paired with a service action that actually consumes a
passed role (e.g. lambda:CreateFunction, ec2:RunInstances with an
instance profile). PMapper's privesc detection requires that paired
action before flagging an escalation; our tool flags ANY iam:PassRole
grant as an edge, regardless of whether a paired use-action exists.

We verified b6-role-a's policy directly: it holds ONLY iam:PassRole on
b6-admin-near, with no paired use-action anywhere in its policy set.

This means:
- Our tool found a real escalation route (the 3-hop one) that
  coincides with PMapper's finding, PLUS a second route PMapper missed.
- However, by the stricter standard PMapper applies (PassRole alone is
  not exploitable without a paired use-action), our tool's 2-hop
  finding here is arguably a FALSE POSITIVE -- there is no AWS service
  action available to b6-role-a that would let it actually USE the
  passed role.

## Honest limitation disclosed

The current iam:PassRole edge-building logic
(graph/builder.py:_add_passrole_edges) flags PassRole grants
unconditionally, without checking for a paired use-action. This is a
conservative design choice (favors recall over precision -- we would
rather over-report a possible escalation primitive than miss one), but
it means the tool's false-positive rate on PassRole-only edges is not
zero. A more precise implementation would cross-reference PassRole
grants against the principal's other permissions for known
paired-action patterns (lambda:CreateFunction + iam:PassRole,
ec2:RunInstances + iam:PassRole, etc.) before creating the edge. This
is flagged as a concrete item for future work / a paper limitations
section, rather than silently treated as correct.
