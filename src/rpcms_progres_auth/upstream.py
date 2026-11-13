"""The boundary to UNHCR ProGres v4.

The real ProGres interface is NOT known to this project. Everything that touches ProGres goes
through ``ProgresClient``: implement it once the interface is confirmed with UNHCR and point
``RPCMS_PROGRES_CLIENT_IMPL`` at your class. Only the two booleans and a reference may cross
this boundary back into RPCMS, never personal data.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable


class UpstreamUnavailable(Exception):
    """ProGres could not be reached or returned something unusable (HTTP 502)."""


class UpstreamTimeout(Exception):
    """ProGres did not answer in time (HTTP 504)."""


@dataclass(frozen=True)
class UpstreamResult:
    authenticated: bool
    record_active: bool
    txn_ref: str


@runtime_checkable
class ProgresClient(Protocol):
    def authenticate(self, progres_id: str, modality: str, biometric_format: str, biometric: bytes) -> UpstreamResult:
        """Ask ProGres: is this person the holder of this ID, and is the record active?

        ``biometric`` is transit-only: send it to ProGres and drop it. Raise
        ``UpstreamUnavailable`` or ``UpstreamTimeout`` on failure.
        """


class MockProgresClient:
    """Development stand-in. Rules (documented so demos are predictable):

    * biometric bytes starting with ``MATCH`` -> authenticated, otherwise not;
    * IDs ending in ``-INACTIVE`` -> record not active;
    * IDs ending in ``-DOWN`` -> upstream unavailable; ``-SLOW`` -> upstream timeout.
    """

    def authenticate(self, progres_id: str, modality: str, biometric_format: str, biometric: bytes) -> UpstreamResult:
        pid = progres_id.upper()
        if pid.endswith("-DOWN"):
            raise UpstreamUnavailable("mock upstream down")
        if pid.endswith("-SLOW"):
            raise UpstreamTimeout("mock upstream timeout")
        ref = f"PGV4-AUTH-{datetime.now(timezone.utc):%Y%m%d}-{secrets.token_hex(3).upper()}"
        return UpstreamResult(
            authenticated=biometric.startswith(b"MATCH"),
            record_active=not pid.endswith("-INACTIVE"),
            txn_ref=ref,
        )
