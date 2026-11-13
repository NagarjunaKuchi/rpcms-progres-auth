# rpcms-progres-auth

Authentication-only adapter between RPCMS (OpenG2P Gen2 refugee partner coordination) and UNHCR ProGres v4.
RPCMS sends a ProGres ID plus a fresh biometric capture; it gets back **Yes/No** and nothing else.

Contract: [`openapi/rpcms-progres-auth.yaml`](openapi/rpcms-progres-auth.yaml). Endpoint: `POST /api/v1/progres/authenticate`.

## What it guarantees
- Response contains only `authenticated`, `recordActive`, `txnRef`, `timestamp`. No name, photo, DOB or household data.
- The biometric is transit-only: decoded, passed to the client, dropped. It is never logged, stored, echoed in errors, or used in the idempotency fingerprint (tests cover logs and validation errors).
- Audit log (`rpcms.progres.audit`, JSON lines) records officer, device, partner, a keyed-hash pseudonym of the ProGres ID, result, txn ref and latency.
- Officer JWT required; token `sub` and `partner_id` must match the request context (403 otherwise). `Idempotency-Key` required; replays return the stored result without calling ProGres again. Per-officer rate limit (429 + `Retry-After`).

## Run
```
pip install -e ".[test]"
export RPCMS_PROGRES_JWT_KEY=...            # >=16 chars (use 32+ for HS256)
export RPCMS_PROGRES_AUDIT_HMAC_KEY=...     # >=16 chars
uvicorn --factory rpcms_progres_auth.api:create_app
pytest
```
Other settings: `RPCMS_PROGRES_JWT_ALGORITHM`, `_JWT_AUDIENCE`, `_RATE_LIMIT_PER_MINUTE`, `_IDEMPOTENCY_TTL_SECONDS`, `_MAX_BIOMETRIC_BYTES`, `_CLIENT_IMPL`.

## Known limits (read before relying on this)
- **The real ProGres interface is not known to this project and nothing here talks to ProGres.** Only `MockProgresClient` exists (dev rules in `upstream.py`). Implement `ProgresClient` after confirming the interface and data-sharing terms with UNHCR, then set `RPCMS_PROGRES_CLIENT_IMPL`.
- Rate limiting and idempotency are in-process; with more than one replica use a shared store (e.g. Redis) or sticky routing.
- Transport security (TLS/mTLS) and token issuance are deployment concerns, not handled here.
- The 403 and 409 responses were added to the contract after the first draft.
- Not a ZKP scheme; it is a boolean answer from ProGres.
