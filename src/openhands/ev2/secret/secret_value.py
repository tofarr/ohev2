"""The :class:`SecretValue` return type exchanged by secret providers.

This is the provider-neutral shape the ``/secret-values`` projection serves.
Providers implement the retrieval-only :class:`SecretProvider` ABC (see
:mod:`secret_provider`) and translate from their own store to this model.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime

from pydantic import BaseModel, Field, field_validator

# A secret ``name`` is env-var compatible: uppercase letters, digits, and
# underscores, with a letter or underscore as the first character.
_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")


class SecretValue(BaseModel):
    """A single secret value served by a :class:`SecretProvider`.

    ``id`` is the composite string ``"{provider_id}/{internal_id}"`` — it is
    deliberately **not** a UUID. External services (AWS Secrets Manager,
    1Password, ...) cannot be guaranteed to use UUIDs for their secret ids, and
    the composite form lets a caller identify both the provider and the secret
    in a single token (parsed with one split): convenient for logging, cache
    keys, and cross-referencing. The REST ``/secret-values/{id}`` path accepts
    the composite string; batch reads key on the string id.

    ``name`` is uppercase letters, digits, and underscores only
    (``[A-Z_][A-Z0-9_]*`` — first character a letter or underscore). Secret
    ids are unique within a provider.
    """

    id: str
    provider_id: uuid.UUID
    internal_id: str
    name: str
    value: str
    valid_at: datetime | None = Field(default=None)
    expires_at: datetime | None = Field(default=None)

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        value = value.strip()
        if not _NAME_RE.match(value):
            raise ValueError("name must match [A-Z_][A-Z0-9_]* (uppercase, digits, underscores)")
        return value

    @classmethod
    def make(
        cls,
        *,
        provider_id: uuid.UUID,
        internal_id: str,
        name: str,
        value: str,
        valid_at: datetime | None = None,
        expires_at: datetime | None = None,
    ) -> SecretValue:
        """Build a :class:`SecretValue`, deriving the composite ``id``.

        The composite id is ``"{provider_id}/{internal_id}"``.
        """
        return cls(
            id=f"{provider_id}/{internal_id}",
            provider_id=provider_id,
            internal_id=internal_id,
            name=name,
            value=value,
            valid_at=valid_at,
            expires_at=expires_at,
        )

    @classmethod
    def split_id(cls, composite_id: str) -> tuple[uuid.UUID, str]:
        """Parse a composite ``{provider_id}/{internal_id}`` id.

        Raises :class:`ValueError` for ids that do not start with a valid UUID
        followed by ``/`` and a non-empty internal id.
        """
        provider, sep, internal = composite_id.partition("/")
        if not sep or not internal:
            raise ValueError(f"Invalid secret value id: {composite_id!r}")
        return uuid.UUID(provider), internal
