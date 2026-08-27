"""Application configuration loaded from environment variables.

Uses the OpenHands SDK env_parser to populate Pydantic models from
environment variables with a structured prefix scheme.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any, Literal, Self, cast

from openhands.agent_server.env_parser import from_env
from pydantic import BaseModel, Field, SecretStr, field_serializer, model_validator


class EncryptionKeyConfig(BaseModel):
    """Configuration for a single encryption/decryption key."""

    id: str = "default"
    value: SecretStr

    @field_serializer("value")
    def serialize_value(self, value: SecretStr, info: Any) -> str:
        if info.context and info.context.get("expose_secrets"):
            return value.get_secret_value()
        return str(value)


class AppConfig(BaseModel):
    """Root application configuration.

    The encryption_key is used for encrypting new data.
    The decryption_keys list contains all keys that can decrypt data,
    enabling key rotation without breaking existing encrypted values.
    The encryption_key is automatically included in decryption_keys.
    base_permissions is a list of permission strings (see permission_grammar)
    applied to every authenticated request as a baseline before per-user DB
    permissions are consulted.
    """

    encryption_key: EncryptionKeyConfig
    decryption_keys: list[EncryptionKeyConfig] = Field(default_factory=list)
    database_url: str = Field(
        default="postgresql+asyncpg://ohev:ohev@localhost:5432/ohev",
        description="Async SQLAlchemy database URL.",
    )
    base_permissions: list[str] = Field(
        default_factory=lambda: ["all:user", "all:permission"],
        description="Baseline permission grants applied to all authenticated users.",
    )
    # Access-token lifetime (OAuth2 flow). Short-lived; replaced via refresh.
    auth_access_token_ttl_seconds: int = Field(
        default=900,
        ge=1,
        description="Lifetime (seconds) of OAuth2 access tokens (JWE).",
    )
    # Refresh-token lifetimes (OAuth2 flow). The sliding window is added to
    # the current time on each newly minted refresh token; the absolute TTL
    # caps how far repeated refreshes can extend a session.
    auth_refresh_token_ttl_seconds: int = Field(
        default=2_592_000,
        ge=1,
        description="Absolute cap (seconds) on the total refresh window.",
    )
    auth_refresh_token_sliding_seconds: int = Field(
        default=86_400,
        ge=1,
        description=("Sliding window (seconds) added to now when minting a refresh token."),
    )
    # Cookie timeout for the password/cookie flow. Each authenticated request
    # re-mints the cookie with a fresh expiry of now + this timeout (sliding
    # session), so an active browser session never expires while idle ones do.
    auth_cookie_timeout_seconds: int = Field(
        default=1800,
        ge=1,
        description=(
            "Sliding timeout (seconds) applied to the session cookie on every "
            "authenticated request."
        ),
    )
    auth_cookie_name: str = Field(
        default="ohesession",
        description="Name of the auth cookie set by the login endpoint.",
    )
    # The session cookie is always Secure (AGENTS.md §9). Hardcoded rather than
    # configurable: a plaintext-transport session cookie is a credential leak,
    # so the flag must never be turned off via the environment.
    auth_cookie_secure: bool = True
    # SameSite attribute for the session cookie. Defaults to "strict" (the
    # strongest browser-side XSRF mitigation): the cookie is never sent on
    # cross-site requests, including top-level navigations from another origin.
    # The auth2 cookie flow is a same-site flow (the client app and API share a
    # site), so strict does not break it. Set to "lax" only if a deployment
    # genuinely needs the cookie on cross-site top-level GET navigations (SSO
    # redirect scenarios), or "none" when the client app is on a different site
    # (then ``auth_cookie_secure`` keeps it HTTPS-only). "none" requires Secure.
    auth_cookie_samesite: Literal["lax", "strict", "none"] = "strict"

    # ------------------------------------------------------------------ #
    # Federated OAuth (auth2) — IdP configuration.
    # The project delegates authentication to an external identity provider
    # (OIDC/OAuth2). These fields wire the federated flow; auth2 runs
    # alongside the legacy auth module until it is proven and merged.
    # ------------------------------------------------------------------ #
    idp_url: str = Field(description="Base URL of the identity provider (OIDC/OAuth2).")
    idp_client_id: str = Field(description="Client id registered at the identity provider.")
    idp_client_secret: SecretStr = Field(
        description="Client secret registered at the identity provider."
    )
    idp_expire_drift_tolerance: int = Field(
        default=60,
        ge=0,
        description=(
            "Seconds subtracted from expires_at / expires_in values returned by "
            "the IdP to avoid treating a token as valid past its real expiry due "
            "to clock drift."
        ),
    )
    # Optional OIDC claim names. When unset, standard OIDC claims are used.
    idp_user_id_field: str | None = Field(
        default=None,
        description=(
            "Claim name in the id_token carrying the stable IdP subject used to "
            "look up the local user. Defaults to the standard 'sub' claim."
        ),
    )
    idp_email_field: str | None = Field(
        default=None, description="Claim name carrying the user email. Defaults to 'email'."
    )
    idp_role_field: str | None = Field(
        default=None,
        description=(
            "Claim name carrying role information. Reserved for future use; "
            "role→permission mapping is deferred."
        ),
    )
    idp_scopes: list[str] = Field(
        default_factory=lambda: ["openid", "email", "profile"],
        description="OAuth scopes requested from the identity provider.",
    )
    idp_authorize_path: str = Field(
        default="/authorize",
        description="Path appended to idp_url for the authorization endpoint.",
    )
    idp_token_path: str = Field(
        default="/token",
        description="Path appended to idp_url for the token exchange endpoint.",
    )
    idp_refresh_path: str = Field(
        default="/token",
        description=(
            "Path appended to idp_url for the refresh-token exchange endpoint. "
            "Defaults to the token endpoint (RFC 6749)."
        ),
    )
    # Lifetime of the *local* access tokens minted by auth2 (JWE). The IdP
    # access token is never exposed to clients; this is the proxy token.
    auth2_access_token_ttl_seconds: int = Field(
        default=900,
        ge=1,
        description="Lifetime (seconds) of auth2 access tokens (JWE).",
    )
    # Public base URL of this service. Used to derive the OAuth callback URL
    # (and any other absolute URLs handed to the IdP / clients). Sourced from
    # config rather than the incoming request so it is correct behind K8s
    # ingresses / proxies that rewrite Host / scheme.
    base_url: str = Field(
        default="http://localhost:8000",
        description="Public base URL of this service (scheme + host[:port]).",
    )

    # ------------------------------------------------------------------ #
    # Background cleanup of expired IdP refresh tokens.
    # ------------------------------------------------------------------ #
    idp_delete_expired_seconds: int = Field(
        default=86_400,
        ge=0,
        description=(
            "Expired IdP refresh tokens older than this many seconds are "
            "eligible for deletion. 0 disables age-based deletion (only "
            "already-expired rows are removed)."
        ),
    )
    cleanup_interval: int = Field(
        default=300,
        ge=0,
        description=(
            "Seconds between background sweeps that delete expired IdP refresh "
            "tokens. When 0 the background loop is disabled and cleanup must be "
            "driven by an external scheduler (cron); see README 'Cleanup "
            "processes'."
        ),
    )

    @model_validator(mode="after")
    def ensure_encryption_key_in_decryption_keys(self) -> Self:
        """Ensure the encryption key is present in decryption_keys."""
        enc_key_id = self.encryption_key.id
        if not any(k.id == enc_key_id for k in self.decryption_keys):
            self.decryption_keys = [self.encryption_key, *self.decryption_keys]
        return self


@lru_cache(maxsize=1)
def get_config() -> AppConfig:
    """Load and cache the application configuration from environment.

    Environment variables are parsed with the 'OHEV' prefix:
      - OHEV_ENCRYPTION_KEY_ID
      - OHEV_ENCRYPTION_KEY_VALUE
      - OHEV_DECRYPTION_KEYS_0_ID
      - OHEV_DECRYPTION_KEYS_0_VALUE
      - OHEV_DECRYPTION_KEYS_1_ID
      - OHEV_DECRYPTION_KEYS_1_VALUE
      - OHEV_BASE_PERMISSIONS_0, OHEV_BASE_PERMISSIONS_1, ...
      ...
    """
    return cast(AppConfig, from_env(AppConfig, "OHEV"))
