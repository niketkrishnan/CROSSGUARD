from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException

from app import scan_service, store
from app.auth import require_api_key
from app.models import GraphResponse, PathsResponse, ScanRequest, ScanSummary

router = APIRouter(prefix="/scans", tags=["scans"], dependencies=[Depends(require_api_key)])


@router.post("", response_model=ScanSummary, status_code=202)
def create_scan(req: ScanRequest, background_tasks: BackgroundTasks) -> ScanSummary:
    """
    Kicks off a scan and returns immediately with status=pending.
    Poll GET /scans/{scan_id} until status is completed or failed.
    """
    scan_id = store.new_scan_id()
    store.create_scan(scan_id, req.name)
    background_tasks.add_task(scan_service.run_scan, scan_id, req)
    return ScanSummary(**store.get_scan(scan_id))


@router.get("", response_model=list[ScanSummary])
def list_scans() -> list[ScanSummary]:
    return [ScanSummary(**s) for s in store.list_scans()]


@router.get("/{scan_id}", response_model=ScanSummary)
def get_scan(scan_id: str) -> ScanSummary:
    scan = store.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    return ScanSummary(**scan)


@router.get("/{scan_id}/graph", response_model=GraphResponse)
def get_graph(scan_id: str) -> GraphResponse:
    scan = store.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    if scan["status"] != "completed":
        raise HTTPException(409, f"Scan is {scan['status']}, not completed yet")
    graph = store.get_graph(scan_id)
    return GraphResponse(scan_id=scan_id, nodes=graph["nodes"], edges=graph["edges"])


@router.get("/{scan_id}/paths", response_model=PathsResponse)
def get_paths(scan_id: str) -> PathsResponse:
    scan = store.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    if scan["status"] != "completed":
        raise HTTPException(409, f"Scan is {scan['status']}, not completed yet")
    return PathsResponse(scan_id=scan_id, paths=store.get_paths(scan_id))
