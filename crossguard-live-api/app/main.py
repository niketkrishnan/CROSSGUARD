from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from app.routers import remediation, scans

logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="CrossGuard Live",
    description=(
        "Web API for CrossGuard: on-demand scanning of an AWS account + "
        "Kubernetes cluster for cross-layer (IRSA) privilege escalation "
        "paths, with graph visualization and guided remediation."
    ),
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans.router)
app.include_router(remediation.router)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


_FRONTEND_INDEX = Path(__file__).parent / "static" / "index.html"


@app.get("/", include_in_schema=False)
def serve_frontend():
    if _FRONTEND_INDEX.exists():
        return FileResponse(_FRONTEND_INDEX)
    return {"detail": "Frontend not bundled in this deployment. API is available at /docs."}
