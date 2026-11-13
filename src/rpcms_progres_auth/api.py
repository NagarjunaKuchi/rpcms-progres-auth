"""FastAPI app implementing openapi/rpcms-progres-auth.yaml.

Privacy rules enforced here: the biometric is decoded, handed to the ProgresClient and dropped;
it is never logged, stored or echoed. Responses carry only AuthResponse fields. Audit lines use a
keyed-hash pseudonym of the ProGres ID.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import importlib
import json
import logging
import time
from datetime import datetime, timezone

import jwt
from fastapi import FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .config import Settings
from .guards import IdempotencyStore, RateLimiter
from .schemas import AuthRequest, AuthResponse
from .upstream import ProgresClient, UpstreamTimeout, UpstreamUnavailable

audit_log = logging.getLogger("rpcms.progres.audit")
PROBLEM = "application/problem+json"


class ApiError(Exception):
    def __init__(self, status: int, title: str, detail: str = "", headers: dict | None = None):
        self.status, self.title, self.detail, self.headers = status, title, detail, headers or {}


def _problem(status: int, title: str, detail: str = "", headers: dict | None = None) -> JSONResponse:
    return JSONResponse({"type": "about:blank", "title": title, "status": status, "detail": detail},
                        status_code=status, media_type=PROBLEM, headers=headers)


def load_client(dotted: str) -> ProgresClient:
    module, _, name = dotted.rpartition(".")
    if not module:
        raise ValueError(f"client_impl must be a dotted path, got {dotted!r}")
    client = getattr(importlib.import_module(module), name)()
    if not isinstance(client, ProgresClient):
        raise TypeError(f"{dotted} does not implement ProgresClient")
    return client


def create_app(settings: Settings | None = None, client: ProgresClient | None = None) -> FastAPI:
    settings = settings or Settings()
    client = client or load_client(settings.client_impl)
    limiter = RateLimiter(settings.rate_limit_per_minute)
    idem = IdempotencyStore(settings.idempotency_ttl_seconds)
    app = FastAPI(title="RPCMS ProGres authentication adapter", version="0.1.0")

    def pseudonym(progres_id: str) -> str:
        return hmac.new(settings.audit_hmac_key.encode(), progres_id.strip().upper().encode(),
                        hashlib.sha256).hexdigest()[:16]

    def claims(authorization: str | None) -> dict:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise ApiError(401, "Missing bearer token")
        try:
            return jwt.decode(
                authorization[7:].strip(), settings.jwt_key, algorithms=[settings.jwt_algorithm],
                audience=settings.jwt_audience,
                options={"require": ["sub", "exp"], "verify_aud": settings.jwt_audience is not None},
            )
        except jwt.PyJWTError:
            raise ApiError(401, "Invalid token")

    def audit(**fields) -> None:
        audit_log.info(json.dumps(fields, sort_keys=True, default=str))

    @app.exception_handler(ApiError)
    async def _api_error(_: Request, e: ApiError):
        return _problem(e.status, e.title, e.detail, e.headers)

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, e: RequestValidationError):
        # Only locations and messages: pydantic's "input" would echo the biometric.
        detail = "; ".join(f"{'.'.join(map(str, x['loc'][1:]))}: {x['msg']}" for x in e.errors())
        return _problem(400, "Invalid request", detail)

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.post("/api/v1/progres/authenticate", response_model=AuthResponse)
    def authenticate(req: AuthRequest, authorization: str | None = Header(default=None),
                     idempotency_key: str | None = Header(default=None)):
        started = time.monotonic()
        c = claims(authorization)
        officer, partner = c["sub"], c.get("partner_id")
        if req.context.officerId != officer or req.context.partnerId != partner:
            raise ApiError(403, "Token does not match request context")
        if not idempotency_key or not (8 <= len(idempotency_key) <= 128):
            raise ApiError(400, "Invalid request", "Idempotency-Key header (8-128 chars) is required")

        # Fingerprint excludes the biometric on purpose (nothing biometric-derived is kept).
        fingerprint = hashlib.sha256(json.dumps(
            [req.progresId, req.modality.value, req.biometric.format, req.context.deviceId,
             req.context.capturedAt.isoformat()]).encode()).hexdigest()
        prior = idem.get(officer, idempotency_key)
        if prior is not None:
            if prior[0] != fingerprint:
                raise ApiError(409, "Idempotency-Key reused with a different request")
            return prior[1]

        wait = limiter.check(officer)
        if wait is not None:
            raise ApiError(429, "Rate limit exceeded", headers={"Retry-After": str(int(wait) + 1)})

        try:
            raw = base64.b64decode(req.biometric.data.get_secret_value(), validate=True)
        except (binascii.Error, ValueError):
            raise ApiError(400, "Invalid request", "biometric.data is not valid base64")
        if not raw or len(raw) > settings.max_biometric_bytes:
            raise ApiError(400, "Invalid request", "biometric.data is empty or too large")

        base = dict(officer=officer, device=req.context.deviceId, partner=partner,
                    id_pseudonym=pseudonym(req.progresId), modality=req.modality.value)
        try:
            res = client.authenticate(req.progresId, req.modality.value, req.biometric.format, raw)
        except UpstreamTimeout:
            audit(**base, result="UPSTREAM_TIMEOUT", latency_ms=int((time.monotonic() - started) * 1000))
            raise ApiError(504, "ProGres timed out")
        except UpstreamUnavailable:
            audit(**base, result="UPSTREAM_UNAVAILABLE", latency_ms=int((time.monotonic() - started) * 1000))
            raise ApiError(502, "ProGres unavailable")
        finally:
            del raw

        body = AuthResponse(authenticated=res.authenticated, recordActive=res.record_active,
                            txnRef=res.txn_ref, timestamp=datetime.now(timezone.utc))
        out = json.loads(body.model_dump_json())
        idem.put(officer, idempotency_key, fingerprint, out)
        audit(**base, result="AUTHENTICATED" if res.authenticated else "NOT_AUTHENTICATED",
              record_active=res.record_active, txn_ref=res.txn_ref,
              latency_ms=int((time.monotonic() - started) * 1000))
        return out

    return app
