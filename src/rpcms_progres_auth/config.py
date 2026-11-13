from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Read from RPCMS_PROGRES_* environment variables."""

    model_config = SettingsConfigDict(env_prefix="RPCMS_PROGRES_", env_file=".env", extra="ignore")

    # Officer tokens (JWT). HS256 with a shared secret, or RS256/ES256 with a PEM public key.
    jwt_key: str = Field(min_length=16)
    jwt_algorithm: str = "HS256"
    jwt_audience: str | None = None

    # Key for the keyed hash used to pseudonymise the ProGres ID in audit logs.
    audit_hmac_key: str = Field(min_length=16)

    rate_limit_per_minute: int = 30  # per officer
    idempotency_ttl_seconds: int = 600
    max_biometric_bytes: int = 512 * 1024

    # Dotted path of the ProGres client. The default is a development mock that talks to nothing.
    client_impl: str = "rpcms_progres_auth.upstream.MockProgresClient"
