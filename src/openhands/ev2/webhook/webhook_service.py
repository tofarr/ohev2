"""Legacy agent-server webhook adapter — translation layer.

Translates the legacy agent-server webhook payloads (SDK ``ConversationInfo``
and the SDK ``Event`` union) into ohev2 ``conversations`` rows and ``events``
projection rows, analogous to the enterprise ``webhook_router.py``. This keeps
compatibility with sandboxes running the current agent server without a
client-side change; sandboxes calling the new REST endpoints directly never
touch this path.

Every mutation is scoped to the :class:`SandboxConfig` resolved from the
``X-Session-API-Key`` header: a sandbox can only upsert conversations backed
by its own config and append events to them. Conversation ids are aligned
with the agent server's ids so the events webhook path parameter resolves.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from openhands.agent_server.models import ConversationInfo
from openhands.sdk import ConversationExecutionStatus
from openhands.sdk.agent.base import AgentBase
from openhands.sdk.conversation.conversation_stats import ConversationStats
from openhands.sdk.event import ConversationStateUpdateEvent
from openhands.sdk.event.base import Event as SdkEvent
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.conversation.conversation_models import Conversation
from openhands.ev2.event.event_models import Event
from openhands.ev2.event.event_schemas import EventCreate
from openhands.ev2.event.event_service import EventService
from openhands.ev2.event.event_store import EventBodyStore
from openhands.ev2.sandbox.sandbox_config_models import SandboxConfig
from openhands.ev2.sandbox.sandbox_session import sandbox_scope_filter

logger = logging.getLogger(__name__)


class WebhookConversationNotFoundError(Exception):
    """Raised when the target conversation is missing or owned by another sandbox."""


def _llm_model_for(agent: AgentBase) -> str | None:
    """The agent's LLM model identifier, when the payload carries one."""
    llm = getattr(agent, "llm", None)
    model = getattr(llm, "model", None)
    return model if isinstance(model, str) and model else None


def _agent_kind_for(agent: AgentBase) -> str:
    """The agent kind discriminator, defaulting to ``openhands``."""
    kind = getattr(agent, "agent_kind", None)
    return kind if isinstance(kind, str) and kind else "openhands"


def _stats_from_value(value: Any) -> ConversationStats | None:
    """Parse a stats event value into :class:`ConversationStats` (best-effort)."""
    if isinstance(value, ConversationStats):
        return value
    if isinstance(value, dict):
        try:
            return ConversationStats.model_validate(value)
        except ValueError:
            logger.warning("unparseable stats event value; skipping metrics update")
    return None


def _metrics_from_stats(stats: ConversationStats | None) -> dict[str, float | int] | None:
    """The absolute metric columns implied by a stats snapshot, or ``None``.

    Combined across every registered LLM usage entry; token totals are the
    cumulative prompt + completion counts the conversation table carries.
    """
    if stats is None or not stats.usage_to_metrics:
        return None
    combined = stats.get_combined_metrics()
    usage = combined.accumulated_token_usage
    if usage is None:
        return {"accumulated_cost": combined.accumulated_cost}
    prompt = usage.prompt_tokens
    completion = usage.completion_tokens
    return {
        "accumulated_cost": combined.accumulated_cost,
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "total_tokens": prompt + completion,
    }


def _event_timestamp(raw: str) -> datetime | None:
    """Parse the SDK event's ISO timestamp; naive values are read as UTC.

    ``None`` means "unparseable — fall back to the server default".
    """
    try:
        ts = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return ts


class WebhookService:
    """Translates legacy webhook payloads into ohev2 rows for one sandbox."""

    def __init__(
        self,
        session: AsyncSession,
        sandbox_config: SandboxConfig,
        *,
        store: EventBodyStore | None = None,
        body_cap_bytes: int = 262_144,
    ) -> None:
        self._session = session
        self._sandbox_config = sandbox_config
        self._store = store
        self._body_cap_bytes = body_cap_bytes

    async def upsert_conversation(self, info: ConversationInfo) -> Conversation | None:
        """Create or update the conversation for a legacy metadata payload.

        Returns ``None`` when the payload reports a deleting conversation
        (mirrors the enterprise adapter: a tombstone signal, not a delete).
        Raises :class:`WebhookConversationNotFoundError` when the conversation
        exists but is backed by a different sandbox config (fail-closed, no
        existence leak).
        """
        if info.execution_status is ConversationExecutionStatus.DELETING:
            return None
        existing = await self._get_unscoped(info.id)
        if existing is not None:
            if existing.sandbox_config_id != self._sandbox_config.id:
                raise WebhookConversationNotFoundError(str(info.id))
            conversation = existing
            self._apply_metadata(conversation, info)
        else:
            conversation = self._create_stub(info)
        metrics = _metrics_from_stats(info.stats)
        if metrics is not None:
            for field, value in metrics.items():
                setattr(conversation, field, value)
        self._session.add(conversation)
        await self._session.flush()
        await self._session.refresh(conversation)
        return conversation

    async def ingest_events(self, conversation_id: uuid.UUID, events: list[SdkEvent]) -> int:
        """Append legacy events to a conversation and fold in stats updates.

        Each SDK event becomes one projection row (kind = the event's
        discriminator, body = the serialized event, timestamp = the event's
        own time). A ``ConversationStateUpdateEvent`` with key ``stats`` also
        updates the conversation's accumulated metric columns.
        """
        conversation = await self._get_unscoped(conversation_id)
        if conversation is None or conversation.sandbox_config_id != self._sandbox_config.id:
            raise WebhookConversationNotFoundError(str(conversation_id))
        event_service = EventService(
            self._session,
            await sandbox_scope_filter(self._session, Event, self._sandbox_config.id),
            store=self._store,
            body_cap_bytes=self._body_cap_bytes,
        )
        for event in events:
            await event_service.create(
                conversation_id,
                EventCreate(kind=event.kind, body=event.model_dump(mode="json")),
                timestamp=_event_timestamp(event.timestamp),
            )
            if isinstance(event, ConversationStateUpdateEvent) and event.key == "stats":
                metrics = _metrics_from_stats(_stats_from_value(event.value))
                if metrics is not None:
                    for field, value in metrics.items():
                        setattr(conversation, field, value)
                    await self._session.flush()
        return len(events)

    async def _get_unscoped(self, conversation_id: uuid.UUID) -> Conversation | None:
        """Fetch a conversation regardless of owner; the caller enforces scope."""
        result = await self._session.execute(
            select(Conversation).where(Conversation.id == conversation_id)
        )
        return result.scalar_one_or_none()

    def _create_stub(self, info: ConversationInfo) -> Conversation:
        """A new conversation row aligned with the agent server's id."""
        conversation = Conversation(
            title=info.title or f"Conversation {info.id.hex}",
            sandbox_config_id=self._sandbox_config.id,
            llm_model=_llm_model_for(info.agent) or "unknown",
            agent_kind=_agent_kind_for(info.agent),
            selected_repository=None,
            selected_branch=None,
            trigger="webhook",
        )
        # ``id`` is init=False on the model; stamp it so the row's id matches
        # the agent server's conversation id (the events webhook keys on it).
        conversation.id = info.id
        return conversation

    @staticmethod
    def _apply_metadata(conversation: Conversation, info: ConversationInfo) -> None:
        """Refresh mutable metadata from a metadata payload (in place)."""
        if info.title:
            conversation.title = info.title
        llm_model = _llm_model_for(info.agent)
        if llm_model is not None:
            conversation.llm_model = llm_model
        conversation.agent_kind = _agent_kind_for(info.agent)
