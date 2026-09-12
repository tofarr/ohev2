"""Pydantic model for the provider-neutral secret surface.

The :class:`Secret` here is an in-memory representation of a secret owned by
the configured :class:`SecretsService` implementation (see
:mod:`openhands.ev2.secret.secret_service`). It is the exchange type between
routers and services: the default SQL-backed implementation keeps its own
ORM models in :mod:`sql_secrets_models` and translates to this Pydantic
model internally, and alternative implementations (AWS Secrets Manager,
1Password, ...) translate from their provider's objects instead.
Implementations may subclass :class:`Secret` to carry provider-specific
fields; the API surface (``SecretRead``) stays unchanged.

The ``value`` never appears on this model — decrypted plaintext is revealed
solely through the ``/secret-values`` projection (AGENTS.md §12).
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from openhands.sdk.utils import utc_now
from pydantic import BaseModel, Field


class SecretType(enum.StrEnum):
    """Discriminator for the kind of payload a secret holds.

    ``STATIC`` — an opaque plaintext value (an API key, token, cert, ...).
    ``OAUTH`` — reserved; OAuth access/refresh token material. No reveal
    support exists yet, so oauth secrets never produce a value.
    """

    STATIC = "static"
    OAUTH = "oauth"


class Secret(BaseModel):
    """A secret's metadata (never its value).

    ``id``, ``created_at``, and ``updated_at`` default to freshly minted
    values so the pre-persistence model built for the create-scope check is
    complete; the provider persists them as given (the SQL implementation
    inserts them explicitly rather than relying on server defaults, so the
    returned model and the stored row agree).
    """

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    code: str
    type: SecretType = SecretType.STATIC
    description: str | None = None
    creator_id: uuid.UUID | None = Field(
        default=None,
        description="The user who created this secret; null when creator is unknown.",
    )
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
