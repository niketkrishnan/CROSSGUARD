"""
Minimal auth so the deployed app isn't a fully open endpoint with
write access to people's cloud accounts.

Starting point: a single shared API key (set via the CROSSGUARD_API_KEY
env var, never committed to the repo). This is intentionally simple --
enough to stop anonymous internet traffic from hitting /scans or
/remediation/*, without building a full user system before you've
even demoed the thing once.

Upgrade path when you have multiple real users (you + your guides,
say): swap this for per-user API keys or a proper login (FastAPI's
OAuth2PasswordBearer + a small user table), without changing any
router code -- they only depend on `require_api_key` below.
"""
from __future__ import annotations

import os
import secrets

from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _expected_key() -> str:
    key = os.environ.get("CROSSGUARD_API_KEY")
    if not key:
        raise RuntimeError(
            "CROSSGUARD_API_KEY is not set. Set it in your deployment's environment "
            "variables before starting the app -- never hardcode it in source."
        )
    return key


def require_api_key(provided: str | None = Depends(_api_key_header)) -> None:
    expected = _expected_key()
    if provided is None or not secrets.compare_digest(provided, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid API key. Pass it as the X-API-Key header.",
        )
