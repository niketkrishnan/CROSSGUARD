"""
Storage layer.

Deliberately in-memory + a single process for the first version --
fine for a demo deployment. Swap this module out for a SQLite/Postgres
version later without touching any router code, since routers only
call the functions below, not the underlying dict.

IMPORTANT: only *results* (graph JSON, paths, risk scores) are ever
stored here. Credentials (AWS temp creds, kubeconfig contents) are
never written into this store -- they live only in local variables
for the duration of a single scan/apply call. See aws_auth.py.
"""
from __future__ import annotations

import secrets
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional

from app.models import EscalationPath, RemediationStatus, ScanStatus

_lock = threading.Lock()

_scans: dict[str, dict] = {}
_graphs: dict[str, dict] = {}          # scan_id -> {"nodes": [...], "edges": [...]}
_paths: dict[str, list[EscalationPath]] = {}  # scan_id -> [EscalationPath, ...]
_confirmations: dict[str, dict] = {}   # confirmation_token -> {"path_id":, "expires_at":}

# Non-secret role config only (role_arn, region, external_id, endpoint override) --
# needed so "apply remediation" can re-assume the role later. Never store the
# temporary access key / secret key / session token here. See aws_auth.py.
_aws_targets: dict[str, dict] = {}     # scan_id -> AWSTarget-shaped dict


def new_scan_id() -> str:
    return secrets.token_hex(8)


def create_scan(scan_id: str, name: str) -> None:
    with _lock:
        _scans[scan_id] = {
            "scan_id": scan_id,
            "name": name,
            "status": ScanStatus.pending,
            "created_at": datetime.now(timezone.utc),
            "completed_at": None,
            "node_count": None,
            "edge_count": None,
            "path_count": None,
            "error": None,
        }


def update_scan(scan_id: str, **fields) -> None:
    with _lock:
        if scan_id in _scans:
            _scans[scan_id].update(fields)


def get_scan(scan_id: str) -> Optional[dict]:
    with _lock:
        return _scans.get(scan_id)


def list_scans() -> list[dict]:
    with _lock:
        return list(_scans.values())


def save_graph(scan_id: str, nodes: list[dict], edges: list[dict]) -> None:
    with _lock:
        _graphs[scan_id] = {"nodes": nodes, "edges": edges}


def get_graph(scan_id: str) -> Optional[dict]:
    with _lock:
        return _graphs.get(scan_id)


def save_paths(scan_id: str, paths: list[EscalationPath]) -> None:
    with _lock:
        _paths[scan_id] = paths


def get_paths(scan_id: str) -> list[EscalationPath]:
    with _lock:
        return _paths.get(scan_id, [])


def get_path(path_id: str) -> Optional[EscalationPath]:
    with _lock:
        for paths in _paths.values():
            for p in paths:
                if p.path_id == path_id:
                    return p
    return None


def update_path_status(path_id: str, status: RemediationStatus) -> None:
    with _lock:
        for paths in _paths.values():
            for i, p in enumerate(paths):
                if p.path_id == path_id:
                    paths[i] = p.model_copy(update={"status": status})
                    return


def save_aws_target(scan_id: str, aws_target: dict) -> None:
    with _lock:
        _aws_targets[scan_id] = aws_target


def get_aws_target(scan_id: str) -> Optional[dict]:
    with _lock:
        return _aws_targets.get(scan_id)


def create_confirmation(path_id: str, ttl_seconds: int = 300) -> tuple[str, datetime]:
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
    with _lock:
        _confirmations[token] = {"path_id": path_id, "expires_at": expires_at}
    return token, expires_at


def consume_confirmation(token: str, path_id: str) -> bool:
    """Validates and invalidates a confirmation token in one step (single-use)."""
    with _lock:
        entry = _confirmations.pop(token, None)
    if entry is None:
        return False
    if entry["path_id"] != path_id:
        return False
    if entry["expires_at"] < datetime.now(timezone.utc):
        return False
    return True
