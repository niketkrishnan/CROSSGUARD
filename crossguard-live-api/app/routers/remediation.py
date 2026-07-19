"""
Two-step apply: /confirm returns a preview + single-use token; /apply
requires that token. This is the guardrail between "the app can execute
fixes" and a bug silently locking someone out of their own AWS/K8s access.

Dispatch note: irsa_bridge fixes are Kubernetes-side (remove the SA
annotation), everything else so far is AWS-side. We don't persist
kubeconfigs between scan and apply (same reasoning as never storing AWS
keys) -- so a K8s-side apply requires kubeconfig_yaml resubmitted in the
apply request.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app import core_adapter, store
from app.auth import require_api_key
from app.aws_auth import AssumeRoleError, assume_role
from app.models import (
    RemediationApplyRequest,
    RemediationApplyResponse,
    RemediationConfirmRequest,
    RemediationConfirmResponse,
    RemediationStatus,
)

router = APIRouter(prefix="/remediation", tags=["remediation"], dependencies=[Depends(require_api_key)])


@router.post("/confirm", response_model=RemediationConfirmResponse)
def confirm_remediation(req: RemediationConfirmRequest) -> RemediationConfirmResponse:
    path = store.get_path(req.path_id)
    if path is None:
        raise HTTPException(404, "Path not found")
    if path.remediation_edge_cut is None:
        raise HTTPException(409, "This path has no remediation computed")

    token, expires_at = store.create_confirmation(req.path_id)
    store.update_path_status(req.path_id, RemediationStatus.pending_confirmation)

    cut = path.remediation_edge_cut
    requires_kubeconfig = cut["edge_type"] in core_adapter.K8S_SIDE_EDGE_TYPES

    preview = (
        f"Will remove the '{cut['edge_type']}' relationship from "
        f"{cut['source']} to {cut['target']}. "
        f"Closes escalation path: {path.entry_node} -> {path.target_node} "
        f"({path.hop_count} hop(s))."
    )
    if requires_kubeconfig:
        preview += " This is a Kubernetes-side fix -- resubmit kubeconfig_yaml with /apply."

    return RemediationConfirmResponse(
        path_id=req.path_id,
        confirmation_token=token,
        expires_at=expires_at,
        preview=preview,
        requires_kubeconfig=requires_kubeconfig,
    )


@router.post("/apply", response_model=RemediationApplyResponse)
def apply_remediation(req: RemediationApplyRequest) -> RemediationApplyResponse:
    path = store.get_path(req.path_id)
    if path is None:
        raise HTTPException(404, "Path not found")
    if path.remediation_edge_cut is None:
        raise HTTPException(409, "This path has no remediation computed")

    if not store.consume_confirmation(req.confirmation_token, req.path_id):
        raise HTTPException(400, "Missing, expired, or already-used confirmation token. Call /remediation/confirm again.")

    cut = path.remediation_edge_cut
    is_k8s_side = cut["edge_type"] in core_adapter.K8S_SIDE_EDGE_TYPES

    try:
        if is_k8s_side:
            if not req.kubeconfig_yaml:
                raise HTTPException(400, "This is a Kubernetes-side fix -- kubeconfig_yaml is required.")
            import tempfile

            with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=True) as tf:
                tf.write(req.kubeconfig_yaml)
                tf.flush()
                core_adapter.apply_k8s_edge_removal(tf.name, cut)
        else:
            aws_target = store.get_aws_target(path.scan_id)
            if aws_target is None:
                raise HTTPException(409, "No AWS target on record for this scan -- cannot apply.")
            creds = assume_role(
                role_arn=aws_target["role_arn"],
                region=aws_target["region"],
                external_id=aws_target["external_id"],
                endpoint_url_override=aws_target["endpoint_url_override"],
                session_name="crossguard-live-remediate",
            )
            iam_client = creds.boto3_client("iam")
            core_adapter.apply_aws_edge_removal(iam_client, cut)

    except AssumeRoleError as exc:
        store.update_path_status(req.path_id, RemediationStatus.failed)
        raise HTTPException(502, f"Could not re-assume role to apply fix: {exc}") from exc
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        store.update_path_status(req.path_id, RemediationStatus.failed)
        raise HTTPException(500, f"Remediation failed: {exc}") from exc

    store.update_path_status(req.path_id, RemediationStatus.applied)

    return RemediationApplyResponse(
        path_id=req.path_id,
        status=RemediationStatus.applied,
        detail="Fix applied. Trigger a new scan against the same target to verify the path is closed.",
    )
