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


class DbConfig(BaseModel):
    """Structured database connection configuration.

    The SQLAlchemy async URL is assembled from these fields rather than read
    as a single connection string, so each component can be injected
    independently (e.g. a secret store populates ``password`` while the rest
    comes from plaintext env vars). Use the ``database_url`` property to get
    the assembled ``postgresql+asyncpg`` URL.
    """

    host: str = Field(default="localhost", description="Database host.")
    port: int = Field(default=5432, ge=1, le=65535, description="Database port.")
    db_name: str = Field(default="ohe", description="Database name.")
    username: str = Field(default="ohe", description="Database username.")
    password: SecretStr = Field(default=SecretStr("ohe"), description="Database password.")

    @property
    def database_url(self) -> str:
        """Assemble the async SQLAlchemy URL from the structured fields."""
        return (
            f"postgresql+asyncpg://{self.username}:"
            f"{self.password.get_secret_value()}@{self.host}:{self.port}/{self.db_name}"
        )


class IdpConfig(BaseModel):
    """Federated OAuth (auth) — identity provider configuration.

    The project delegates authentication to an external identity provider
    (OIDC/OAuth2). It acts as an OAuth provider to first-party clients and an
    OAuth client to the IdP. These fields wire the federated flow; auth runs
    alongside the legacy auth module until it is proven and merged.
    """

    url: str = Field(
        default="/auth/dev",
        description=(
            "Base URL of the identity provider (OIDC/OAuth2). Defaults to the "
            "built-in dev identity provider mounted at '/auth/dev' "
            "(see auth.dev_router); set this to a real IdP URL for production."
        ),
    )
    client_id: str = Field(
        default="ohe",
        description="Client id registered at the identity provider.",
    )
    client_secret: SecretStr = Field(
        default=SecretStr("change-me"),
        description="Client secret registered at the identity provider.",
    )
    expire_drift_tolerance: int = Field(
        default=60,
        ge=0,
        description=(
            "Seconds subtracted from expires_at / expires_in values returned by "
            "the IdP to avoid treating a token as valid past its real expiry due "
            "to clock drift."
        ),
    )
    # Optional OIDC claim names. When unset, standard OIDC claims are used.
    user_id_field: str | None = Field(
        default=None,
        description=(
            "Claim name in the id_token carrying the stable IdP subject used to "
            "look up the local user. Defaults to the standard 'sub' claim."
        ),
    )
    email_field: str | None = Field(
        default=None, description="Claim name carrying the user email. Defaults to 'email'."
    )
    role_field: str | None = Field(
        default=None,
        description=(
            "Claim name carrying role information. Reserved for future use; "
            "role→permission mapping is deferred."
        ),
    )
    scopes: list[str] = Field(
        default_factory=lambda: ["openid", "email", "profile"],
        description="OAuth scopes requested from the identity provider.",
    )
    authorize_path: str = Field(
        default="/authorize",
        description="Path appended to idp.url for the authorization endpoint.",
    )
    token_path: str = Field(
        default="/token",
        description="Path appended to idp.url for the token exchange endpoint.",
    )
    refresh_path: str = Field(
        default="/token",
        description=(
            "Path appended to idp.url for the refresh-token exchange endpoint. "
            "Defaults to the token endpoint (RFC 6749)."
        ),
    )
    revocation_path: str | None = Field(
        default=None,
        description=(
            "Path appended to idp.url for the RFC 7009 token revocation "
            "endpoint. When unset (the default), revocation is local-only: "
            "the project's own tokens are revoked but the underlying IdP "
            "credential is not. Set this (e.g. '/revoke') when the IdP "
            "exposes a revocation endpoint so /auth/revoke also forwards the "
            "best-effort revocation to the IdP. IdP revocation failures are "
            "swallowed — the local revocation always succeeds."
        ),
    )
    # Fallback access-token lifetime (seconds) used only when the IdP token
    # response omits both ``expires_in`` and ``expires_at``. The IdP is the
    # source of truth for access control; this is a last-resort default.
    access_token_expires_in: int = Field(
        default=900,
        ge=1,
        description=(
            "Fallback access-token lifetime (seconds) when the IdP does not "
            "advertise one. The IdP-advertised expiry is always preferred."
        ),
    )
    # Fallback refresh-token lifetime (seconds) used only when the IdP token
    # response omits a refresh-token expiry (``refresh_expires_in`` /
    # ``refresh_expires_at``). The IdP is the source of truth when present.
    refresh_token_expires_in: int = Field(
        default=2_592_000,
        ge=1,
        description=(
            "Fallback refresh-token lifetime (seconds) when the IdP does not "
            "advertise one. The IdP-advertised expiry is always preferred."
        ),
    )
    # Lock timeout (seconds) for the DB row lock held during an IdP refresh.
    # If a concurrent refresh holds the lock longer than this, the waiter
    # abandons the refresh rather than blocking indefinitely.
    refresh_lock_timeout_seconds: float = Field(
        default=5.0,
        gt=0,
        description=(
            "Max seconds to wait for the refresh-row lock during a concurrent "
            "IdP token refresh. On timeout the refresh is abandoned with an "
            "error so the client can retry / re-authenticate."
        ),
    )
    # Background cleanup of expired IdP refresh tokens.
    delete_expired_seconds: int = Field(
        default=86_400,
        ge=0,
        description=(
            "Expired IdP refresh tokens older than this many seconds are "
            "eligible for deletion. 0 disables age-based deletion (only "
            "already-expired rows are removed)."
        ),
    )


class AppConfig(BaseModel):
    """Root application configuration.

    The encryption_key is used for encrypting new data.
    The decryption_keys list contains all keys that can decrypt data,
    enabling key rotation without breaking existing encrypted values.
    The encryption_key is automatically included in decryption_keys.
    """

    encryption_key: EncryptionKeyConfig
    decryption_keys: list[EncryptionKeyConfig] = Field(default_factory=list)
    idp: IdpConfig = Field(
        default_factory=IdpConfig,
        description="Identity provider (federated OAuth / OIDC) configuration.",
    )
    db_config: DbConfig = Field(
        default_factory=DbConfig,
        description="Structured database connection configuration (host/port/db/credentials).",
    )
    # Minted-token lifetimes are NOT configurable here: they are always synced
    # to the expiries advertised by the IdP (with idp.* fallbacks when the IdP
    # omits one). See IdpConfig.access_token_expires_in /
    # refresh_token_expires_in and AuthService._mint_access_token /
    # _mint_refresh_token / _mint_cookie_jwe. The app server never grants
    # access beyond what the IdP sanctions.
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
    # The auth cookie flow is a same-site flow (the client app and API share a
    # site), so strict does not break it. Set to "lax" only if a deployment
    # genuinely needs the cookie on cross-site top-level GET navigations (SSO
    # redirect scenarios), or "none" when the client app is on a different site
    # (then ``auth_cookie_secure`` keeps it HTTPS-only). "none" requires Secure.
    auth_cookie_samesite: Literal["lax", "strict", "none"] = "strict"

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

    @property
    def database_url(self) -> str:
        """Assembled async SQLAlchemy database URL (from ``db_config``)."""
        return self.db_config.database_url


@lru_cache(maxsize=1)
def get_config() -> AppConfig:
    """Load and cache the application configuration from environment.

    Environment variables are parsed with the 'OHE' prefix:
      - OHE_ENCRYPTION_KEY_ID
      - OHE_ENCRYPTION_KEY_VALUE
      - OHE_DECRYPTION_KEYS_0_ID
      - OHE_DECRYPTION_KEYS_0_VALUE
      - OHE_DECRYPTION_KEYS_1_ID
      - OHE_DECRYPTION_KEYS_1_VALUE
      - OHE_DB_CONFIG_HOST, OHE_DB_CONFIG_PORT, OHE_DB_CONFIG_DB_NAME,
        OHE_DB_CONFIG_USERNAME, OHE_DB_CONFIG_PASSWORD
      - OHE_IDP_URL, OHE_IDP_CLIENT_ID, OHE_IDP_CLIENT_SECRET, ...
      ...
    """
    return cast(AppConfig, from_env(AppConfig, "OHE"))
