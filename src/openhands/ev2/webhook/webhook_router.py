"""Legacy agent-server webhook adapter — HTTP routes.

Receives the *old* agent server's webhook payloads and translates them into
ohev2 ``conversations``/``events`` rows (see ``webhook_service.py``), keeping
compatibility with sandboxes running the current agent server without a
client-side change. Mirrors the enterprise ``webhook_router.py`` surface:

* ``POST /webhooks/{sandbox_config_id}/conversations`` — conversation
  metadata upsert.
* ``POST /webhooks/{sandbox_config_id}/conversations/{conversation_id}/events``
  — event batch append (also folds ``stats`` state-update events into the
  conversation's metrics).

The callback URL carries the sandbox config id it claims; authorization is
the standard role-policy path — ``depends_permissions`` resolves the
principal's filter for conversation CREATE/UPDATE and event CREATE
(``X-API-KEY`` API keys included; no bespoke header). The service then
checks the filter ``matches`` the candidate or existing row alongside the
URL-scoped config checks.
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from openhands.agent_server.models import ConversationInfo, Success
from openhands.sdk.event.base import Event as SdkEvent

from openhands import tools
from openhands.ev2.auth.auth_dependencies import (
    depends_permissions,
    depends_permissions_or_none,
)
from openhands.ev2.config import get_config
from openhands.ev2.conversation.conversation_models import Conversation
from openhands.ev2.db import SessionDep
from openhands.ev2.event.event_models import Event
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import SearchFilter
from openhands.ev2.webhook.webhook_service import (
    WebhookConversationNotFoundError,
    WebhookSandboxNotFoundError,
    WebhookService,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

ConversationCreateFilterDep = Annotated[
    SearchFilter[Conversation],
    Depends(depends_permissions(Conversation, Action.CREATE)),
]
ConversationUpdateFilterDep = Annotated[
    SearchFilter[Conversation] | None,
    Depends(depends_permissions_or_none(Conversation, Action.UPDATE)),
]
EventCreateFilterDep = Annotated[
    SearchFilter[Event],
    Depends(depends_permissions(Event, Action.CREATE)),
]

# The stats-folding metric update is best-effort: it additionally consults the
# Conversation UPDATE filter (``None`` → fold skipped), so routes only depend
# on what their payload needs.


def _service(
    session: SessionDep,
    config_id: uuid.UUID,
    conversation_create: SearchFilter[Conversation] | None,
    conversation_update: SearchFilter[Conversation] | None,
    event_create: SearchFilter[Event] | None,
) -> WebhookService:
    """Build the per-request adapter service from config (store, cap)."""
    cfg = get_config()
    return WebhookService(
        session,
        config_id,
        conversation_create,
        conversation_update,
        event_create,
        store=cfg.get_event_store(),
        body_cap_bytes=cfg.event.body_cap_bytes,
    )


def _map_scope_errors(exc: Exception) -> HTTPException:
    """404 for unknown scopes — existence of configs/conversations is not leaked."""
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.post("/{sandbox_config_id}/conversations", response_model=Success)
async def on_conversation_update(
    sandbox_config_id: uuid.UUID,
    payload: ConversationInfo,
    session: SessionDep,
    conversation_create: ConversationCreateFilterDep,
    conversation_update: ConversationUpdateFilterDep,
) -> Success:
    """Webhook callback for conversation starts/pauses/resumes/deletes."""
    service = _service(session, sandbox_config_id, conversation_create, conversation_update, None)
    try:
        await service.upsert_conversation(payload)
    except (WebhookConversationNotFoundError, WebhookSandboxNotFoundError) as exc:
        raise _map_scope_errors(exc) from exc
    await session.commit()
    return Success()


@router.post("/{sandbox_config_id}/conversations/{conversation_id}/events", response_model=Success)
async def on_event(
    sandbox_config_id: uuid.UUID,
    conversation_id: uuid.UUID,
    payload: list[SdkEvent],
    session: SessionDep,
    event_create: EventCreateFilterDep,
    conversation_update: ConversationUpdateFilterDep,
) -> Success:
    """Webhook callback for event-stream events of one conversation."""
    service = _service(session, sandbox_config_id, None, conversation_update, event_create)
    try:
        await service.ingest_events(conversation_id, payload)
    except (WebhookConversationNotFoundError, WebhookSandboxNotFoundError) as exc:
        raise _map_scope_errors(exc) from exc
    await session.commit()
    return Success()


def _import_all_tools() -> None:
    """Import all tools so custom event kinds deserialize in webhooks."""
    for _, name, is_pkg in pkgutil.walk_packages(tools.__path__, tools.__name__ + "."):
        if is_pkg:  # Check if it's a subpackage
            try:
                importlib.import_module(name)
            except ImportError:
                logger.exception("Warning: Could not import subpackage %r", name)


_import_all_tools()
