"""Legacy agent-server webhook adapter — translation layer.

Translates the legacy agent-server webhook payloads (SDK ``ConversationInfo``
and the SDK ``Event`` union) into ohev2 ``conversations`` rows and ``events``
projection rows, analogous to the enterprise ``webhook_router.py``. This keeps
compatibility with sandboxes running the current agent server without a
client-side change; sandboxes calling the new REST endpoints directly never
touch this path.

The callback URL carries the target ``sandbox_config_id``; authorization is
the standard role-policy path: the principal's ``conversation_permission``
CREATE/UPDATE filter must match the prospective (create) or existing
(refresh) conversation, and their ``event_permission`` CREATE filter must
match the appended events. A conversation outside the URL's sandbox config
is invisible (404).
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
from openhands.ev2.util.search_filter import AllSearchFilter, SearchFilter

logger = logging.getLogger(__name__)


class WebhookSandboxNotFoundError(Exception):
    """Raised when the URL's sandbox config id is unknown (404)."""


class WebhookConversationNotFoundError(Exception):
    """Raised when the target conversation is missing or out of scope (404)."""


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
    prompt = usage.prompt_tokens if usage is not None else 0
    completion = usage.completion_tokens if usage is not None else 0
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
    """Translates legacy webhook payloads into ohev2 rows for one sandbox.

    Holds the URL's sandbox config id and the role-policy filters the router
    resolved for the principal. Any of the three filters may be ``None``
    (no grant): the operations that need it then fail closed.
    """

    def __init__(
        self,
        session: AsyncSession,
        config_id: uuid.UUID,
        conversation_create: SearchFilter[Conversation] | None,
        conversation_update: SearchFilter[Conversation] | None,
        event_create: SearchFilter[Event] | None,
        *,
        store: EventBodyStore | None = None,
        body_cap_bytes: int = 262_144,
    ) -> None:
        self._session = session
        self._config_id = config_id
        self._conversation_create = conversation_create
        self._conversation_update = conversation_update
        self._event_create = event_create
        self._store = store
        self._body_cap_bytes = body_cap_bytes

    async def upsert_conversation(self, info: ConversationInfo) -> Conversation | None:
        """Create or update the conversation for a legacy metadata payload.

        Returns ``None`` when the payload reports a deleting conversation
        (mirrors the enterprise adapter: a tombstone signal, not a delete).
        Raises :class:`WebhookSandboxNotFoundError` when the URL's config is
        unknown (404), and :class:`WebhookConversationNotFoundError` when
        the conversation exists but is backed by a different sandbox config
        or the principal's role policies deny it (fail-closed, no existence
        leak, 404).
        """
        await self._require_config()
        if info.execution_status is ConversationExecutionStatus.DELETING:
            return None
        existing = await self._get_unscoped(info.id)
        if existing is not None:
            if existing.sandbox_config_id != self._config_id:
                raise WebhookConversationNotFoundError(str(info.id))
            update = self._conversation_update
            if update is None or not update.matches(existing):
                raise WebhookConversationNotFoundError(str(info.id))
            conversation = existing
            self._apply_metadata(conversation, info)
        else:
            conversation = self._create_stub(info)
            create = self._conversation_create
            if create is None or not create.matches(conversation):
                raise WebhookConversationNotFoundError(str(info.id))
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
        own time). A ``ConversationStateUpdateEvent`` with key ``stats``
        also updates the conversation's accumulated metric columns when the
        conversation UPDATE filter allows it (skips otherwise — best-effort,
        like the enterprise adapter).
        """
        await self._require_config()
        conversation = await self._get_unscoped(conversation_id)
        if conversation is None or conversation.sandbox_config_id != self._config_id:
            raise WebhookConversationNotFoundError(str(conversation_id))
        candidate = Event(conversation_id=conversation_id, kind="", body={}, size_bytes=0)
        if self._event_create is None or not self._event_create.matches(candidate):
            raise WebhookConversationNotFoundError(str(conversation_id))
        # The event filter above already authorized the append; EventService
        # requires a non-None filter, so admit-all here.
        event_service = EventService(
            self._session,
            AllSearchFilter[Event](),
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
                update = self._conversation_update
                if update is None or not update.matches(conversation):
                    continue
                metrics = _metrics_from_stats(_stats_from_value(event.value))
                if metrics is not None:
                    for field, value in metrics.items():
                        setattr(conversation, field, value)
                    await self._session.flush()
        return len(events)

    async def _require_config(self) -> None:
        """The URL's sandbox config must exist (the callback's scope identity)."""
        config = await self._session.get(SandboxConfig, self._config_id)
        if config is None:
            raise WebhookSandboxNotFoundError(str(self._config_id))

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
            sandbox_config_id=self._config_id,
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
