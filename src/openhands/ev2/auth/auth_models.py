"""Domain and ORM models for the auth feature.

Tokens are JWE-encrypted JWT payloads carrying standard claims that the
:class:`AuthToken` domain model derives its fields from:

========== ==================================================
AuthToken  JWT claim
========== ==================================================
id         ``jti`` (token id, shared with DB rows where present)
user_id    ``sub``
created_at ``iat``
updated_at ``iat`` (tokens are immutable; JWE payloads carry no timestamp
           for a later modification, so it aliases ``iat``)
expires_at ``exp``
token_type ``ttyp`` (custom claim; there is no standard JWT claim for
           token type)
enabled    not a claim — resolved from the user row (COOKIE/ACCESS_TOKEN)
           or the token's DB row and the user row (API_KEY/REFRESH_TOKEN)
========== ==================================================

Two token types additionally have DB entities whose validity is checked as
part of authentication (AGENTS.md §9 — defense in depth):

* ``API_KEY``: a long-lived JWE token whose ``jti`` must match a live
  ``api_keys`` row (enabled, unexpired).
* ``REFRESH_TOKEN``: a JWE token whose ``jti`` must match a live
  ``refresh_tokens`` row (enabled, unexpired); rotation invalidates the row
  and mints a successor with a fresh ``jti``.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict
from sqlalchemy import DateTime, ForeignKey, func
from sqlalchemy.orm import Mapped, mapped_column

from openhands.ev2.db import Base

# All auth timestamps are timezone-aware (TIMESTAMPTZ) so comparisons against
# datetime.now(UTC) never mix naive and aware values. This differs from the
# legacy users table (naive TIMESTAMP) but is the correct forward direction.
_TZ = DateTime(timezone=True)


class TokenType(enum.StrEnum):
    """The kind of credential a token represents.

    COOKIE and ACCESS_TOKEN are short-lived JWE tokens validated against the
    user row only. API_KEY and REFRESH_TOKEN are additionally validated
    against their DB rows.
    """

    COOKIE = "cookie"
    API_KEY = "api_key"
    ACCESS_TOKEN = "access_token"
    REFRESH_TOKEN = "refresh_token"
    # auth2 (federated OAuth) refresh token. Exchange-only: never accepted as a
    # bearer credential by AuthService.authenticate. Handled by the auth2
    # refresh endpoint, which validates it against the idp_refresh_tokens row.
    IDP_REFRESH_TOKEN = "idp_refresh_token"


class AuthToken(BaseModel):
    """The decrypted view of a credential, normalized across all flows.

    Field derivation from JWT claims is documented on the module docstring;
    ``enabled`` is resolved by :class:`AuthService` (see module docstring).
    """

    model_config = ConfigDict(frozen=True)

    id: uuid.UUID
    user_id: uuid.UUID
    created_at: datetime
    updated_at: datetime
    enabled: bool
    expires_at: datetime
    token_type: TokenType


class ApiKey(Base):
    """A revocable backing row for an API-key credential.

    The row shares its ``jti`` with the API-key JWE token minted for it; a
    token whose jti has no live row is rejected even if the JWE itself is
    decryptable and unexpired.
    """

    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    # Shared with the JWE `jti` claim so authentication can join on it.
    jti: Mapped[uuid.UUID] = mapped_column(unique=True, index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    name: Mapped[str | None] = mapped_column(default=None, nullable=True)
    enabled: Mapped[bool] = mapped_column(default=True, server_default="true")
    expires_at: Mapped[datetime | None] = mapped_column(
        _TZ,
        default=None,
        nullable=True,
        comment="Null means the API key never expires on its own.",
    )
    created_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class RefreshToken(Base):
    """A backing row for a refresh-token credential.

    Rotation invalidates the row (``enabled = False``) and mints a successor
    token with a fresh ``jti``. ``expires_at`` is the absolute cap of the
    sliding window: each rotation extends a *new* row's expiry to
    ``min(now + sliding_window, first_issued_at + absolute_ttl)``.

    Field order is constrained by the dataclass protocol: fields without
    defaults precede those with defaults.
    """

    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    # Shared with the JWE `jti` claim of the refresh token.
    jti: Mapped[uuid.UUID] = mapped_column(unique=True, index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    expires_at: Mapped[datetime] = mapped_column(
        _TZ,
        comment="Absolute cap of the sliding refresh window.",
    )
    # The successor row created by rotating this token; null until rotated.
    # The chain of rotations lets a family be invalidated wholesale.
    replaced_by: Mapped[uuid.UUID | None] = mapped_column(
        default=None,
        nullable=True,
    )
    enabled: Mapped[bool] = mapped_column(default=True, server_default="true")
    created_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
