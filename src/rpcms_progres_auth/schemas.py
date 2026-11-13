from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, SecretStr


class Modality(str, Enum):
    FACE = "FACE"
    FINGERPRINT = "FINGERPRINT"


class Biometric(BaseModel):
    model_config = ConfigDict(extra="forbid")
    format: Annotated[str, Field(min_length=1, max_length=64)]
    # SecretStr keeps the value out of repr(), logs and error messages.
    data: SecretStr


class Context(BaseModel):
    model_config = ConfigDict(extra="forbid")
    deviceId: Annotated[str, Field(min_length=1, max_length=128)]
    officerId: Annotated[str, Field(min_length=1, max_length=64)]
    partnerId: Annotated[str, Field(min_length=1, max_length=64)]
    capturedAt: datetime


class AuthRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    progresId: Annotated[str, Field(min_length=3, max_length=64)]
    modality: Modality
    biometric: Biometric
    context: Context


class AuthResponse(BaseModel):
    """Everything RPCMS is allowed to learn. No name, photo, date of birth or household data."""

    authenticated: bool
    recordActive: bool
    txnRef: str
    timestamp: datetime
