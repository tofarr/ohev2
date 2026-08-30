"""ORM models for the LLM feature.

Two stored tables mirror the SDK's :class:`ProviderConnection` and
:class:`LLM` so the project can persist and govern LLM credentials/profiles
like any other resource (per AGENTS.md §3/§9), while still producing the SDK
objects an agent needs at runtime.

* :class:`StoredProviderConnection` — a shared credential bundle (provider,
  ``api_key``, ``base_url``) reused by one or more stored LLMs. The ``api_key``
  is encrypted at rest (JWE ciphertext, like ``OAuthClient.client_secret``).
  The ``id`` is a UUID (the SDK's :class:`ProviderConnection.id` is a string;
  the stored id is stringified when materializing the SDK object). An
  ``enable_proxy`` flag selects whether the connection's effective ``base_url``
  points at this service's proxy completion endpoint (built from
  :attr:`AppConfig.base_url`) or at the stored ``base_url``.
* :class:`StoredLLM` — an LLM profile. Unlike the SDK :class:`LLM` it carries
  no ``provider``, ``api_key`` or ``base_url`` of its own: those are sourced
  from its non-nullable :class:`StoredProviderConnection` at materialization
  time. Everything else on the SDK :class:`LLM` (retry/temperature/caps/…) is
  persisted verbatim as a JSONB ``config`` blob.

Both models expose a ``to_*`` method that materializes the corresponding SDK
object. The encryption service is injected so the model stays a pure data
holder; the caller (service/router) owns cipher lifecycle.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

import sqlalchemy as sa
from pydantic import SecretStr
from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Numeric,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from openhands.ev2.db import Base
from openhands.ev2.encryption.encryption_service import EncryptionService

if TYPE_CHECKING:  # avoid runtime import of the SDK at module import time
    from openhands.sdk.llm.llm import LLM
    from openhands.sdk.llm.provider_connection_store import ProviderConnection


class StoredProviderConnection(Base):
    """A shared LLM provider credential bundle.

    The ``api_key`` is encrypted at rest (JWE ciphertext). ``enable_proxy``
    selects the effective ``base_url`` handed to the SDK: when ``True`` the
    connection points at this service's proxy completion endpoint (so LLM
    traffic is routed through this API); when ``False`` the stored
    ``base_url`` is used directly.
    """

    __tablename__ = "provider_connections"
    __table_args__ = {"comment": "Shared LLM provider credential bundles (encrypted api_key)"}  # noqa: RUF012

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    display_name: Mapped[str] = mapped_column(String(128))
    provider: Mapped[str] = mapped_column(String(128), default="custom")
    # Encrypted API key (JWE ciphertext); null when unset.
    api_key: Mapped[str | None] = mapped_column(
        String(8192),
        default=None,
        nullable=True,
    )
    base_url: Mapped[str | None] = mapped_column(
        String(2048),
        default=None,
        nullable=True,
    )
    enable_proxy: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default="false",
    )
    created_at: Mapped[datetime] = mapped_column(
        init=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        init=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    llms: Mapped[list[StoredLLM]] = relationship(
        init=False,
        back_populates="provider_connection",
        cascade="all, delete-orphan",
    )

    def to_provider_connection(
        self,
        enc: EncryptionService,
        *,
        proxy_url: str | None = None,
        use_proxy: bool = True,
    ) -> ProviderConnection:
        """Materialize the SDK :class:`ProviderConnection` for this row.

        ``api_key`` is decrypted via *enc* (returns ``None`` when unset). When
        ``enable_proxy`` and ``use_proxy`` are ``True`` the effective
        ``base_url`` is *proxy_url*; otherwise the stored ``base_url`` is used.
        ``id`` is stringified and timestamps are Unix epoch seconds.
        """
        from openhands.sdk.llm.provider_connection_store import ProviderConnection

        api_key_plaintext: str | None = None
        if self.api_key is not None:
            api_key_plaintext = enc.decrypt_value(self.api_key)

        effective_base_url = proxy_url if self.enable_proxy and use_proxy else self.base_url

        now = int(time.time())
        created = int(self.created_at.timestamp()) if self.created_at is not None else now
        updated = int(self.updated_at.timestamp()) if self.updated_at is not None else now

        return ProviderConnection(
            id=str(self.id),
            display_name=self.display_name,
            provider=self.provider,
            api_key=SecretStr(api_key_plaintext) if api_key_plaintext else None,
            base_url=effective_base_url,
            created_at=created,
            updated_at=updated,
        )


class StoredLLM(Base):
    """A stored LLM profile.

    The SDK :class:`LLM`'s ``provider``/``api_key``/``base_url`` are NOT stored
    here — they come from the non-nullable :class:`StoredProviderConnection`.
    Everything else on the SDK :class:`LLM` is persisted as the JSONB
    ``config`` blob (a serialized ``LLM.model_dump()`` minus the
    connection-sourced fields).
    """

    __tablename__ = "llms"
    __table_args__ = {"comment": "Stored LLM profiles referencing a provider connection"}  # noqa: RUF012

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    provider_connection_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("provider_connections.id", ondelete="CASCADE"),
        index=True,
    )
    model: Mapped[str] = mapped_column(String(255))
    display_name: Mapped[str] = mapped_column(String(128))
    config: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default_factory=dict,
        comment=(
            "Serialized SDK LLM config (all fields except model/provider/"
            "api_key/base_url, which are sourced from the provider connection)."
        ),
    )
    created_at: Mapped[datetime] = mapped_column(
        init=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        init=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    provider_connection: Mapped[StoredProviderConnection] = relationship(
        init=False,
        back_populates="llms",
        lazy="selectin",
    )

    def to_llm(self, connection: ProviderConnection) -> LLM:
        """Materialize the SDK :class:`LLM` from this profile + a connection.

        *connection* is the SDK :class:`ProviderConnection` (materialized from
        the linked :class:`StoredProviderConnection`) supplying ``api_key``,
        ``base_url`` and ``provider_connection_id``. The stored ``config`` blob
        supplies every other SDK field; ``model`` comes from this row.
        """
        from openhands.sdk.llm.llm import LLM

        fields: dict[str, object] = dict(self.config)
        # Connection-sourced fields take precedence over anything in the blob.
        fields["model"] = self.model
        fields["api_key"] = connection.api_key
        fields["base_url"] = connection.base_url
        fields["provider_connection_id"] = connection.id
        return LLM.model_validate(fields)


# ---------------------------------------------------------------------- #
# LLM usage logging
# ---------------------------------------------------------------------- #


class LlmUsage(Base):
    """Raw, append-only record of a single LLM completion invocation.

    One row per proxied ``POST /llm/completion/{id}`` call. The table is
    PostgreSQL range-partitioned by ``created_at`` (one daily partition), so
    old partitions can be dropped cheaply by the background partition manager.
    The composite primary key ``(id, created_at)`` is required for partitioning
    (every column in the partition key must be part of the PK); ``id`` is a
    bigint identity so the row is cheap to insert and orderable by recency.

    This raw table is **not** exposed over REST — usage queries go through the
    :class:`LlmAggregatedUsage` projection. Background loops (see
    :mod:`openhands.ev2.llm.llm_service`) keep future daily partitions
    allocated, drop expired ones, and roll per-minute aggregations.
    """

    __tablename__ = "llm_usage"
    __table_args__ = {  # noqa: RUF012
        "postgresql_partition_by": "RANGE(created_at)",
        "comment": "Raw LLM invocation records, daily-partitioned by created_at",
    }

    id: Mapped[int] = mapped_column(
        BigInteger,
        sa.Identity(always=False, start=1, increment=1),
        primary_key=True,
        init=False,
    )
    # Partition key — must be part of the PK and NOT NULL for range partitioning.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        primary_key=True,
        init=False,
        server_default=func.now(),
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    provider_connection_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("provider_connections.id", ondelete="CASCADE"),
        index=True,
    )
    llm_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("llms.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
        default=None,
    )
    response_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        default=None,
    )
    model: Mapped[str] = mapped_column(String(255), default="")
    # Token metrics mirrored from the SDK MetricsSnapshot / TokenUsage so the
    # raw record stays queryable without rehydrating the SDK object. All
    # default to 0 — a provider that omits a metric records 0, not NULL.
    prompt_tokens: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    completion_tokens: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    cache_read_tokens: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    cache_write_tokens: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    reasoning_tokens: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    context_window: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    per_turn_token: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    accumulated_cost: Mapped[float] = mapped_column(Numeric(18, 6), default=0.0, server_default="0")
    # The full SDK MetricsSnapshot dump (model_name, max_budget_per_task, …) for
    # any metric not lifted into a dedicated column. Keeps the raw record
    # forward-compatible with new SDK metric fields without a migration.
    metrics: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default_factory=dict,
        comment="Full SDK MetricsSnapshot dump (model_dump(mode='json')).",
    )


class LlmAggregatedUsage(Base):
    """Per-minute, per-user rollup of :class:`LlmUsage` for usage queries.

    One row per ``(user_id, minute)`` that had at least one invocation. Sums the
    token/metric columns and counts invocations; the background aggregator
    populates it one minute at a time, always at least one minute behind real
    time so a finished minute is never partially aggregated. Minutes without
    usage are not inserted (the requirement is "no row for no usage").

    This is the table exposed read-only over REST (``/llm/aggregated-usage``).
    """

    __tablename__ = "llm_aggregated_usage"
    __table_args__ = (
        UniqueConstraint("user_id", "minute", name="uq_llm_aggregated_usage_user_id_minute"),
        {"comment": "Per-minute, per-user rollup of llm_usage"},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    # UTC minute bucket (seconds zeroed) — the aggregation grain.
    minute: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    invocations: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    prompt_tokens: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    completion_tokens: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    cache_read_tokens: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    cache_write_tokens: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    reasoning_tokens: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    context_window: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    per_turn_token: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    accumulated_cost: Mapped[float] = mapped_column(Numeric(18, 6), default=0.0, server_default="0")
    created_at: Mapped[datetime] = mapped_column(
        init=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        init=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


__all__ = [
    "LlmAggregatedUsage",
    "LlmUsage",
    "StoredLLM",
    "StoredProviderConnection",
]
