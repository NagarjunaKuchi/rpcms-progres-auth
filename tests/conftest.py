import base64
import time

import jwt
import pytest
from fastapi.testclient import TestClient

from rpcms_progres_auth.api import create_app
from rpcms_progres_auth.config import Settings

KEY = "test-signing-key-0123456789-abcdef"


@pytest.fixture
def settings():
    return Settings(jwt_key=KEY, audit_hmac_key="audit-key-0123456789", rate_limit_per_minute=5)


@pytest.fixture
def client(settings):
    return TestClient(create_app(settings))


def token(officer="off-1", partner="PRT-2026-0187", key=KEY, exp=300):
    return jwt.encode({"sub": officer, "partner_id": partner, "exp": int(time.time()) + exp}, key, algorithm="HS256")


def payload(pid="UGA-00423318", bio=b"MATCH-face-template", officer="off-1", partner="PRT-2026-0187"):
    return {"progresId": pid, "modality": "FACE",
            "biometric": {"format": "ISO-19794-5", "data": base64.b64encode(bio).decode()},
            "context": {"deviceId": "dev-9", "officerId": officer, "partnerId": partner,
                        "capturedAt": "2026-11-13T08:00:00Z"}}


def post(client, body=None, tok=None, idem="idem-key-0001"):
    h = {"Authorization": f"Bearer {tok or token()}"}
    if idem:
        h["Idempotency-Key"] = idem
    return client.post("/api/v1/progres/authenticate", json=body or payload(), headers=h)
