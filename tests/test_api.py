import base64
import logging

import pytest
from fastapi.testclient import TestClient

from rpcms_progres_auth.api import create_app, load_client
from rpcms_progres_auth.config import Settings
from rpcms_progres_auth.upstream import MockProgresClient, UpstreamResult

from conftest import payload, post, token


def test_match_returns_only_whitelisted_fields(client):
    r = post(client)
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"authenticated", "recordActive", "txnRef", "timestamp"}
    assert body["authenticated"] is True and body["recordActive"] is True
    assert body["txnRef"].startswith("PGV4-AUTH-")


def test_no_match_and_inactive(client):
    assert post(client, payload(bio=b"OTHER"), idem="idem-key-0002").json()["authenticated"] is False
    b = post(client, payload(pid="UGA-1-INACTIVE"), idem="idem-key-0003").json()
    assert b["authenticated"] is True and b["recordActive"] is False


def test_upstream_errors(client):
    assert post(client, payload(pid="UGA-1-DOWN"), idem="idem-key-0004").status_code == 502
    assert post(client, payload(pid="UGA-1-SLOW"), idem="idem-key-0005").status_code == 504


def test_auth_failures(client):
    assert client.post("/api/v1/progres/authenticate", json=payload()).status_code == 401
    assert post(client, tok=token(key="x" * 32)).status_code == 401
    assert post(client, tok=token(exp=-10)).status_code == 401
    assert post(client, tok=token(officer="someone-else")).status_code == 403
    assert post(client, tok=token(partner="PRT-OTHER")).status_code == 403


def test_idempotency_replay_and_reuse(settings):
    calls = []

    class Counting(MockProgresClient):
        def authenticate(self, *a):
            calls.append(1)
            return super().authenticate(*a)

    c = TestClient(create_app(settings, Counting()))
    first = post(c, idem="idem-key-0010").json()
    again = post(c, idem="idem-key-0010").json()
    assert first == again and len(calls) == 1
    assert post(c, payload(pid="UGA-99999"), idem="idem-key-0010").status_code == 409
    assert post(c, idem=None).status_code == 400


def test_rate_limit_per_officer(client):
    codes = [post(client, idem=f"idem-key-{i:04d}").status_code for i in range(7)]
    assert codes[:5] == [200] * 5 and codes[5:] == [429, 429]
    r = post(client, idem="idem-key-9999")
    assert r.headers["Retry-After"].isdigit()
    other = post(client, payload(officer="off-2"), tok=token(officer="off-2"), idem="idem-key-8888")
    assert other.status_code == 200


def test_validation_errors_never_echo_biometric(client):
    secret = base64.b64encode(b"MATCH-SECRET-TEMPLATE").decode()
    bad = payload()
    bad["modality"] = "IRIS"
    r = post(client, bad)
    assert r.status_code == 400 and r.headers["content-type"].startswith("application/problem+json")
    assert secret not in r.text
    bad = payload()
    bad["biometric"]["data"] = "!!not base64!!"
    assert post(client, bad, idem="idem-key-0020").status_code == 400
    big = payload(bio=b"M" * (512 * 1024 + 1))
    assert post(client, big, idem="idem-key-0021").status_code == 400
    extra = payload()
    extra["name"] = "x"
    assert post(client, extra, idem="idem-key-0022").status_code == 400


def test_biometric_never_in_logs(client, caplog):
    caplog.set_level(logging.DEBUG)
    bio = b"MATCH-UNIQUE-TEMPLATE-BYTES"
    post(client, payload(bio=bio))
    post(client, payload(bio=bio, pid="UGA-1-DOWN"), idem="idem-key-0030")
    text = caplog.text
    assert "rpcms.progres.audit" in text
    assert base64.b64encode(bio).decode() not in text and bio.decode() not in text
    assert "UGA-00423318" not in text  # only the pseudonym is logged


def test_load_client_validation():
    assert isinstance(load_client("rpcms_progres_auth.upstream.MockProgresClient"), MockProgresClient)
    with pytest.raises(ValueError):
        load_client("nodots")
    with pytest.raises(TypeError):
        load_client("collections.OrderedDict")


def test_settings_reject_short_keys():
    with pytest.raises(Exception):
        Settings(jwt_key="short", audit_hmac_key="audit-key-0123456789")


def test_healthz(client):
    assert client.get("/healthz").json() == {"status": "ok"}
