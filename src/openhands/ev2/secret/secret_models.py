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

import uuid
from datetime import datetime

from openhands.sdk.utils import utc_now
from pydantic import BaseModel, Field


class Secret(BaseModel):
    """A secret's metadata (never its value).

    Every secret holds one opaque plaintext value (an API key, token, cert,
    ...). External OAuth providers are integrated separately (e.g. the
    federated-IdP token tables in ``auth/``), not as secrets.

    ``id``, ``created_at``, and ``updated_at`` default to freshly minted
    values so the pre-persistence model built for the create-scope check is
    complete; the provider persists them as given (the SQL implementation
    inserts them explicitly rather than relying on server defaults, so the
    returned model and the stored row agree).
    """

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    code: str
    description: str | None = None
    creator_id: uuid.UUID | None = Field(
        default=None,
        description="The user who created this secret; null when creator is unknown.",
    )
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
