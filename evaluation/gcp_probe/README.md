# GCP Cross-Cloud Generalizability Probe

Supports Section 11 of `evaluation_complete_final.md`.

- `gcp_probe.py`: constructs a GCP Workload Identity Federation scenario
  directly as a graph (matching the exact schema `build_unified_graph`
  produces), runs it through the real, unmodified `pathfinder/search.py`.
  First-attempt result: 0 paths — a genuine negative caused by
  `is_cross_layer()` having a hardcoded `"aws"` type-prefix check rather
  than a generic non-k8s check.
- `gcp_probe_v2.py`: same scenario, with that one check broadened (via
  monkeypatch, not editing the actual repo file) to "not k8s" instead of
  literal "aws". Demonstrates the rest of the pipeline (pathfinding, risk
  scoring, remediation) requires zero further changes to handle a new
  cloud provider's node types correctly.
