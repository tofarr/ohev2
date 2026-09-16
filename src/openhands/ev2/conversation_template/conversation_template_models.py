"""ORM model for the conversation template resource.

A :class:`ConversationTemplate` is the durable, reusable "launch profile" for
starting conversations from the enterprise server — the ohev2 replacement for
the enterprise ``user.conversation_settings`` / ``user.agent_settings`` (which
were bound to users/orgs). The template is a DB-backed, permission-governed row
created by an admin/operator and referenced at start-conversation time (issue
#2).

It resolves once the parts of a start-conversation request that are **not**
per-invocation and **not** sandbox-specific:

* ``agent_kind`` — the ``AgentSettings`` discriminator (``openhands``/``acp``).
* ``llm_id`` — FK to the governed :class:`StoredLLM` to use, ``ON DELETE SET
  NULL`` (a deleted LLM nulls the template's default; the start path errors if
  the resolved LLM is ``None``).
* ``mcp_server_config_ids`` / ``secret_provider_ids`` / ``static_secret_ids``
  — FKs to governed rows the start path projects into the conversation.
* ``agent_config`` — JSONB blob of the remaining ``AgentSettings`` fields
  (mirrors how ``StoredLLM.config`` persists SDK fields verbatim).
* ``conversation_config`` — JSONB blob of the template-level
  :class:`ConversationConfig` fields (``confirmation_policy``,
  ``security_analyzer``, ``max_iterations``, ``stuck_detection``,
  ``tool_module_qualnames``, ``client_tools``, ``worktree``). Per-start fields
  (``workspace``, ``conversation_id``, ``initial_message``,
  ``parent_conversation_id``) are intentionally not on the template.
* ``system_message_suffix`` — optional static suffix; the planning-agent
  prefix and HOST context are applied by the start service, not stored.
* ``default_callbacks`` — list of :class:`EventCallback` callables to
  auto-attach to every conversation started from this template.

Ownership is direct via ``creator_id`` (unlike :class:`Conversation`, which
derives ownership from its backing sandbox config). Access is governed by the
``conversation_template_permission`` role column; see
``conversation_template_security`` and AGENTS.md §11.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from openhands.ev2.db import Base
from openhands.ev2.event_callback.event_callback_models import (
    EventCallback,
    EventCallbackListType,
)

_TZ = DateTime(timezone=True)


class ConversationTemplate(Base):
    """A durable, reusable conversation launch profile."""

    __tablename__ = "conversation_templates"
    __table_args__ = {"comment": "Reusable conversation launch profiles (admin-governed)"}  # noqa: RUF012

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    creator_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    name: Mapped[str] = mapped_column(
        String(255),
        comment="Human-readable launch profile name.",
    )
    # The ``AgentSettings`` discriminator ('openhands' / 'acp'). Stored as a
    # free string (like ``Conversation.agent_kind``); the schema layer validates
    # the allowed values.
    agent_kind: Mapped[str] = mapped_column(
        String(32),
        default="openhands",
        comment="AgentSettings discriminator ('openhands' or 'acp').",
    )
    # ON DELETE SET NULL: a deleted LLM nulls the template's default; the start
    # path errors when the resolved LLM is None. Not a relationship so deleting
    # an LLM never cascades to templates.
    llm_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("llms.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
        default=None,
        comment="FK to the governed StoredLLM to use; null after the LLM is deleted.",
    )
    # List of stringified UUIDs (JSONB). These are plain references — not FK
    # columns — so no DB-level cascade; the start path resolves them and errors
    # on dangling ids.
    mcp_server_config_ids: Mapped[list[str]] = mapped_column(
        JSONB,
        default_factory=list,
        comment="Governed MCPServerConfig ids to load into conversations.",
    )
    secret_provider_ids: Mapped[list[str]] = mapped_column(
        JSONB,
        default_factory=list,
        comment="Governed SecretProvider ids to project into the secrets map.",
    )
    static_secret_ids: Mapped[list[str]] = mapped_column(
        JSONB,
        default_factory=list,
        comment="Governed StaticSecret ids to project into the secrets map.",
    )
    agent_config: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default_factory=dict,
        comment="SDK AgentSettings fields (minus llm/mcp/secrets, which are governed rows).",
    )
    conversation_config: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default_factory=dict,
        comment="Template-level SDK ConversationConfig fields.",
    )
    system_message_suffix: Mapped[str | None] = mapped_column(
        Text,
        default=None,
        nullable=True,
        comment="Optional static suffix appended by the start service.",
    )
    default_callbacks: Mapped[list[EventCallback]] = mapped_column(
        EventCallbackListType,
        default_factory=list,
        comment="EventCallback callables auto-attached by the start service.",
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
