"""
Pydantic schemas for the CrossGuard Live API.

We never accept or store long-lived AWS secret keys -- only "assume this
role ARN". K8s access uses a submitted kubeconfig, which (like AWS creds)
is never persisted; see store.py for what is and isn't kept.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class ScanStatus(str, Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class RemediationStatus(str, Enum):
    not_applied = "not_applied"
    pending_confirmation = "pending_confirmation"
    applied = "applied"
    failed = "failed"


# ---------------------------------------------------------------------------
# Scan request / target configuration
# ---------------------------------------------------------------------------

class AWSTarget(BaseModel):
    role_arn: str = Field(..., description="IAM role in the target account to assume.")
    external_id: Optional[str] = Field(default=None)
    region: str = Field(default="us-east-1")
    endpoint_url_override: Optional[str] = Field(
        default=None, description="Set to http://localhost:4566 for LocalStack demo runs."
    )


class K8sTarget(BaseModel):
    kubeconfig_yaml: str = Field(..., description="Raw kubeconfig content.")
    context: Optional[str] = Field(default=None)


class ScanRequest(BaseModel):
    name: str
    aws_target: AWSTarget
    k8s_target: K8sTarget


class ScanSummary(BaseModel):
    scan_id: str
    name: str
    status: ScanStatus
    created_at: datetime
    completed_at: Optional[datetime] = None
    node_count: Optional[int] = None
    edge_count: Optional[int] = None
    path_count: Optional[int] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Graph output
# ---------------------------------------------------------------------------

class GraphNode(BaseModel):
    id: str
    label: str
    layer: str  # "aws" | "k8s"
    node_type: str  # aws_user / aws_role / aws_group / k8s_service_account / k8s_role / k8s_cluster_role
    is_admin: bool = False
    on_vulnerable_path: bool = False


class GraphEdge(BaseModel):
    source: str
    target: str
    edge_type: str  # sts:AssumeRole / iam:PassRole / group_membership / irsa_bridge / rbac binding types
    on_vulnerable_path: bool = False


class GraphResponse(BaseModel):
    scan_id: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]


# ---------------------------------------------------------------------------
# Paths + remediation
# ---------------------------------------------------------------------------

class EscalationPath(BaseModel):
    path_id: str
    scan_id: str
    entry_node: str
    target_node: str
    node_sequence: list[str]
    hop_count: int
    risk_score: float
    cross_layer: bool
    remediation_summary: Optional[str] = None
    remediation_commands: list[str] = Field(default_factory=list)
    remediation_edge_cut: Optional[dict] = None  # {"source":, "target":, "edge_type":}
    status: RemediationStatus = RemediationStatus.not_applied


class PathsResponse(BaseModel):
    scan_id: str
    paths: list[EscalationPath]


# ---------------------------------------------------------------------------
# Remediation apply flow -- two-step confirm, see routers/remediation.py
# ---------------------------------------------------------------------------

class RemediationConfirmRequest(BaseModel):
    path_id: str


class RemediationConfirmResponse(BaseModel):
    path_id: str
    confirmation_token: str
    expires_at: datetime
    preview: str
    requires_kubeconfig: bool = Field(
        description="True if this fix is K8s-side (e.g. removing an IRSA annotation) "
        "and /remediation/apply will need kubeconfig_yaml re-submitted."
    )


class RemediationApplyRequest(BaseModel):
    path_id: str
    confirmation_token: str
    kubeconfig_yaml: Optional[str] = Field(
        default=None,
        description="Required only when the fix is K8s-side. We don't persist "
        "kubeconfigs between the scan and the apply call, so it must be "
        "resubmitted here -- same reasoning as never storing AWS keys.",
    )


class RemediationApplyResponse(BaseModel):
    path_id: str
    status: RemediationStatus
    detail: str
