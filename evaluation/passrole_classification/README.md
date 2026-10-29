# PassRole Two-Tier Classification (Confirmed vs. Conservative-Potential)

`classify_passrole_paths.py` re-derives every AWS-to-AWS hop's real edge
type by querying LIVE LocalStack trust/permission policies directly
(not the graph, which keeps only one edge type per node pair). A hop is
`passrole_bare` if the source has an iam:PassRole grant on the target with
NO independently-redundant sts:AssumeRole trust relationship between the
same two principals. A path is Confirmed if every hop is AssumeRole-backed;
Conservative-Potential if at least one hop is bare PassRole.

Final verified split (all re-run fresh against live LocalStack, zero
contaminated/stale runs):

| Path | Verdict |
|---|---|
| B1, B3 (no PassRole hop) | Confirmed |
| B2 (3-hop, both AssumeRole-backed) | Confirmed |
| B6-far (AssumeRole-backed) | Confirmed |
| B6-near | Conservative-Potential |
| B8 x2 | Conservative-Potential |
| B9 Case A, Case C | Conservative-Potential |
| B11 wildcard-principal (no PassRole hop, but see caveat below) | Confirmed* |
| B11 nested-conditions | Conservative-Potential |
| B11 4-hop (5-node) chain | Conservative-Potential |

*B11 wildcard: single-hop irsa_bridge only, no AWS-to-AWS hop at all --
wildcard trust (`Principal: {"AWS": "*"}`) is never evaluated (confirmed
directly in `graph/builder.py`: `if principal_arn == "*": continue`).
Detection came entirely from IRSA binding, not wildcard-trust modeling.
The paper should not claim wildcard-trust detection based on this case.

B10's two Condition-blindness false positives (explicit Deny, MFA-gated
trust) are a SEPARATE, already-documented limitation -- not part of this
PassRole classification.
