"""ORM model for persisted sandbox configurations.

A :class:`SandboxConfig` represents the durable *intent* for a sandbox: which
template to use, whether the sandbox should be enabled, an optional snapshot
to restore from, the encrypted session API key, and an expiry. The live
sandbox (the Docker container / K8s deployment) is not stored here — the
sandbox service reconciles live sandboxes to match these configs.

``enabled`` replaces the prior ``desired_status`` lifecycle state. Disabling
is provider-interpreted: Docker pauses or deletes-and-recreates (governed by
``OHE_SANDBOX_DEACTIVATE_MODE``); K8s snapshots (if ``snapshot_on_deactivate``)
and deletes, recreating from ``sandbox_snapshot_id`` on re-enable.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from openhands.ev2.db import Base

_TZ = DateTime(timezone=True)


class SandboxConfig(Base):
    """Durable intent for a sandbox (DB-backed, provider-neutral).

    The sandbox service reads ``enabled``, ``sandbox_snapshot_id``, and the
    linked template to reconcile the live sandbox. ``session_api_key`` is
    encrypted at rest (JWE ciphertext, same pattern as
    :class:`StoredProviderConnection.api_key`).

    ``expires_at`` is derived from the template's
    ``delete_after_idle_seconds`` by the lifecycle sweep and refreshed as the
    sandbox idles.
    """

    __tablename__ = "sandbox_configs"
    __table_args__ = {"comment": "Durable sandbox intent (DB-backed source of truth)"}  # noqa: RUF012

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    creator_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    sandbox_template_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sandbox_templates.id", ondelete="RESTRICT"),
        index=True,
    )
    # Encrypted JWE ciphertext of the session API key; never exposed in plaintext
    # through the API (SandboxConfigRead omits it; the live Sandbox carries it).
    session_api_key: Mapped[str] = mapped_column(
        String(8192),
        comment="Encrypted session API key for the sandbox (JWE ciphertext).",
    )
    # Non-secret SHA-256 of the plaintext session API key. The ingestion path
    # resolves an inbound ``X-Session-API-Key`` header to this config by hash
    # (see sandbox_session.py) without ever storing the plaintext.
    session_api_key_hash: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        index=True,
        comment="SHA-256 hex of the plaintext session API key (lookup hash).",
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default="false",
        comment="Whether the live sandbox should be running. The service reconciles to this.",
    )
    sandbox_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        nullable=True,
        default=None,
        comment="Optional snapshot to restore when (re)creating the live sandbox.",
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        _TZ,
        nullable=True,
        default=None,
        comment="Derived from the template's delete_after_idle_seconds by the lifecycle sweep.",
    )
    snapshot_on_deactivate: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default="false",
        comment="Read from the template on create if not explicitly set.",
    )
    meta: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default_factory=dict,
        comment="Provider-specific hints for this sandbox config.",
    )
    created_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.clock_timestamp(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.clock_timestamp(),
        onupdate=func.now(),
    )

    sandbox_template: Mapped[SandboxTemplate] = relationship(
        init=False,
        back_populates="sandbox_configs",
    )


# Re-exported here so ``from sandbox_config_models import SandboxConfig`` works
# and the string annotation on SandboxTemplate.sandbox_configs resolves.
from openhands.ev2.sandbox.sandbox_template_models import SandboxTemplate  # noqa: E402
