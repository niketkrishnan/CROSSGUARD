from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

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

# TODO: restrict allow_origins to your actual deployed frontend URL before
# going live -- "*" is fine for local dev only.
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
