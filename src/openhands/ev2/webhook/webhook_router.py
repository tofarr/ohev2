"""Legacy agent-server webhook adapter — HTTP routes.

Receives the *old* agent server's webhook payloads and translates them into
ohev2 ``conversations``/``events`` rows (see ``webhook_service.py``), keeping
compatibility with sandboxes running the current agent server without a
client-side change. Mirrors the enterprise ``webhook_router.py`` surface:

* ``POST /webhooks/conversations`` — conversation metadata upsert.
* ``POST /webhooks/events/{conversation_id}`` — event batch append (also
  folds ``stats`` state-update events into the conversation's metrics).

Both routes authenticate via ``depends_sandbox_config`` (the
``X-Session-API-Key`` header resolved to a :class:`SandboxConfig`) — a
bespoke, sandbox-only mechanism; user credentials are not accepted here.
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
from openhands.ev2.config import get_config
from openhands.ev2.db import SessionDep
from openhands.ev2.sandbox.sandbox_config_models import SandboxConfig
from openhands.ev2.sandbox.sandbox_session import depends_sandbox_config
from openhands.ev2.webhook.webhook_service import (
    WebhookConversationNotFoundError,
    WebhookService,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


def _service(session: SessionDep, sandbox_config: SandboxConfig) -> WebhookService:
    """Build the per-request adapter service from config (store, cap)."""
    cfg = get_config()
    return WebhookService(
        session,
        sandbox_config,
        store=cfg.get_event_store(),
        body_cap_bytes=cfg.event.body_cap_bytes,
    )


@router.post("/conversations", response_model=Success)
async def on_conversation_update(
    payload: ConversationInfo,
    session: SessionDep,
    sandbox_config: Annotated[SandboxConfig, Depends(depends_sandbox_config)],
) -> Success:
    """Webhook callback for conversation starts/pauses/resumes/deletes."""
    service = _service(session, sandbox_config)
    try:
        await service.upsert_conversation(payload)
    except WebhookConversationNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Conversation not found: {exc}",
        ) from exc
    await session.commit()
    return Success()


@router.post("/events/{conversation_id}", response_model=Success)
async def on_event(
    conversation_id: uuid.UUID,
    payload: list[SdkEvent],
    session: SessionDep,
    sandbox_config: Annotated[SandboxConfig, Depends(depends_sandbox_config)],
) -> Success:
    """Webhook callback for event-stream events of one conversation."""
    service = _service(session, sandbox_config)
    try:
        await service.ingest_events(conversation_id, payload)
    except WebhookConversationNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Conversation not found: {exc}",
        ) from exc
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
