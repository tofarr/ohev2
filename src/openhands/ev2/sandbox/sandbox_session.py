"""Sandbox session-key authentication for the ingestion path.

A running sandbox authenticates to ohev2 with the session API key minted for
its :class:`SandboxConfig` (sent as the ``X-Session-API-Key`` header, matching
the legacy agent-server webhook convention). The plaintext key is never
stored — :class:`SandboxConfig` carries its JWE ciphertext plus a non-secret
SHA-256 ``session_api_key_hash`` — so the inbound key is looked up by hash
and resolves to exactly one config. Every mutation is then scoped to the
conversation(s) whose ``sandbox_config_id`` matches the resolved config: the
sandbox token is never the creator's user session.

The scope is expressed as ordinary :class:`SearchFilter` instances so the
conversation/event services enforce it exactly like a role-derived filter
(defense in depth, AGENTS.md §9).
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Annotated, overload

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from openhands.ev2.conversation.conversation_models import Conversation
from openhands.ev2.db import SessionDep
from openhands.ev2.event.event_models import Event
from openhands.ev2.sandbox.sandbox_config_models import SandboxConfig
from openhands.ev2.util.search_filter import SearchFilter

SESSION_API_KEY_HEADER = "X-Session-API-Key"

_sandbox_session_scheme = APIKeyHeader(
    name=SESSION_API_KEY_HEADER,
    scheme_name="SandboxSessionKey",
    auto_error=False,
    description="Sandbox session API key; scoped to the sandbox's own conversations.",
)


def hash_session_api_key(plaintext_key: str) -> str:
    """The non-secret SHA-256 lookup hash of a plaintext session API key."""
    return hashlib.sha256(plaintext_key.encode("utf-8")).hexdigest()


async def resolve_sandbox_config_by_session_key(
    session: AsyncSession,
    plaintext_key: str,
) -> SandboxConfig | None:
    """Resolve a plaintext session API key to its :class:`SandboxConfig`.

    The lookup is by the indexed SHA-256 hash; ``None`` means the key is
    unknown (the caller answers 401).
    """
    stmt = select(SandboxConfig).where(
        SandboxConfig.session_api_key_hash == hash_session_api_key(plaintext_key)
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def depends_sandbox_config(
    session: SessionDep,
    session_api_key: Annotated[str | None, Security(_sandbox_session_scheme)],
) -> SandboxConfig:
    """FastAPI dependency: resolve ``X-Session-API-Key`` to its config, or 401.

    Used by the sandbox-only ingestion surface (the legacy webhook adapter),
    where a user credential is *not* an acceptable substitute — the routes
    authenticate through this bespoke mechanism rather than the standard
    permission dependency (AGENTS.md §9, PERMISSION_DEPENDENCY_OVERRIDES).
    """
    if session_api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"{SESSION_API_KEY_HEADER} header is required.",
        )
    config = await resolve_sandbox_config_by_session_key(session, session_api_key)
    if config is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid session API key.",
        )
    return config


class SandboxConversationScopeFilter(SearchFilter[Conversation]):
    """Scope admitting only conversations backed by one sandbox config.

    The ingestion scope for a resolved sandbox credential: the sandbox may act
    on conversations whose ``sandbox_config_id`` equals its own config's id —
    no per-conversation ACL is involved, so a conversation is in scope from
    the moment it is created.
    """

    sandbox_config_id: uuid.UUID

    def matches(self, item: Conversation) -> bool:
        return item.sandbox_config_id == self.sandbox_config_id

    def sql_condition(self) -> ColumnElement[bool] | None:
        return Conversation.sandbox_config_id == self.sandbox_config_id


class SandboxEventScopeFilter(SearchFilter[Event]):
    """Scope admitting only events of conversations backed by one sandbox config.

    ``conversation_ids`` backs the in-memory check (the create path validates
    a not-yet-flushed event, so only ``conversation_id`` is available); the
    SQL path uses a subquery so it stays current as conversations are added.
    """

    sandbox_config_id: uuid.UUID
    conversation_ids: frozenset[uuid.UUID]

    def matches(self, item: Event) -> bool:
        return item.conversation_id in self.conversation_ids

    def sql_condition(self) -> ColumnElement[bool] | None:
        return Event.conversation_id.in_(
            select(Conversation.id).where(Conversation.sandbox_config_id == self.sandbox_config_id)
        )


@overload
async def sandbox_scope_filter(
    session: AsyncSession,
    model_type: type[Conversation],
    sandbox_config_id: uuid.UUID,
) -> SandboxConversationScopeFilter: ...


@overload
async def sandbox_scope_filter(
    session: AsyncSession,
    model_type: type[Event],
    sandbox_config_id: uuid.UUID,
) -> SandboxEventScopeFilter: ...


async def sandbox_scope_filter(
    session: AsyncSession,
    model_type: type,
    sandbox_config_id: uuid.UUID,
) -> SearchFilter[Conversation] | SearchFilter[Event]:
    """Build the ingestion scope filter for *model_type*.

    Only the resources a sandbox credential may mutate are supported:
    conversations (metadata updates) and events (appends).
    """
    if model_type is Conversation:
        return SandboxConversationScopeFilter(sandbox_config_id=sandbox_config_id)
    if model_type is Event:
        result = await session.execute(
            select(Conversation.id).where(Conversation.sandbox_config_id == sandbox_config_id)
        )
        return SandboxEventScopeFilter(
            sandbox_config_id=sandbox_config_id,
            conversation_ids=frozenset(result.scalars().all()),
        )
    raise ValueError(f"No sandbox scope for {model_type.__name__!r}")
