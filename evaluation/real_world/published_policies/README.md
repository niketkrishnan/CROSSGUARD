# Real-world published-policy set (RWP)

*For the case-by-case justification of these five cases, see [`../../../BENCHMARK_CASE_CATALOG.md`](../../../BENCHMARK_CASE_CATALOG.md), category 9.*

Four verbatim, currently-published IAM policies from widely-deployed AWS EKS add-ons (AWS Load Balancer Controller, EBS CSI Driver, EFS CSI Driver, Cluster Autoscaler), plus one case modeling a pattern documented in a Unit 42 industry threat report. Offline and live-verified, 5/5.

- `policies.py` — the verbatim policy text, with source URLs and fetch dates.
- `build_cases.py` — assembles each policy into a full test case (IRSA trust, ServiceAccount mapping).
- `run_offline.py` — in-memory accuracy check.
- `live_verify.py` — LocalStack + Minikube live verification.

Full narrative: `evaluation/policy_semantics/POLICY_SEMANTICS_EVALUATION.md`, section 11.

Reproduce:
```
python -m evaluation.real_world.published_policies.run_offline
python -m evaluation.real_world.published_policies.live_verify > /tmp/rwp_live.sh && bash /tmp/rwp_live.sh
```
