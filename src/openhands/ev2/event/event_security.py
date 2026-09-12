"""Permission policy and search filter for the event resource.

Events use a custom permission policy, :class:`EventAccess`, that — like
:class:`ConversationAccess` — grants non-admin users **search and read only**,
scoped to events on conversations backed by a sandbox config the user
created. All write actions are denied to them; events are created by the
ingestion path (or admin principals), not by end users.

The scope check cannot reuse :class:`CreatorPermission`: ``Event`` has no
``creator_id`` of its own — ownership derives from the parent conversation's
backing sandbox config, so the SQL condition joins through ``conversations``
→ ``sandbox_configs``.

A role with ``event_permission = Permitted()`` (the seeded admin role)
bypasses this entirely and gets full access — handled by :class:`Permitted`,
not this policy, exactly as ``conversation_permission`` works.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.sql.elements import ColumnElement

from openhands.ev2.conversation.conversation_models import Conversation
from openhands.ev2.event.event_models import Event
from openhands.ev2.sandbox.sandbox_config_models import SandboxConfig
from openhands.ev2.security.security_models import Action, Permission
from openhands.ev2.util.search_filter import (
    NoneSearchFilter,
    SearchFilter,
    T,
)


class EventAccessFilter(SearchFilter[T]):
    """Filter admitting events whose conversation is backed by an owned sandbox config.

    Admits an :class:`Event` iff its ``conversation_id`` resolves to a
    :class:`Conversation` whose ``sandbox_configs.creator_id == user_id``.
    Expressed both in-memory (via the eagerly loaded ``conversation`` →
    ``sandbox_config`` relationships) and in SQL (an ``IN`` subquery so
    collection endpoints push the scope into the DB). The SQL path is
    authoritative for collection endpoints; the in-memory path requires the
    relationships to be loaded and denies when they are not.
    """

    user_id: uuid.UUID

    def matches(self, item: T) -> bool:
        conversation = getattr(item, "conversation", None)
        if conversation is None:
            return False
        sandbox_config = getattr(conversation, "sandbox_config", None)
        return sandbox_config is not None and sandbox_config.creator_id == self.user_id

    def sql_condition(self) -> ColumnElement[bool] | None:
        return Event.conversation_id.in_(
            select(Conversation.id).where(
                Conversation.sandbox_config_id.in_(
                    select(SandboxConfig.id).where(SandboxConfig.creator_id == self.user_id)
                )
            )
        )


class EventAccess(Permission):
    """Read/search-only policy scoped to events of the principal's own conversations.

    ``SEARCH`` and ``READ`` reduce to :class:`EventAccessFilter`;
    ``CREATE``, ``UPDATE``, and ``DELETE`` reduce to :class:`NoneSearchFilter`
    (deny). Anonymous principals (``user_id is None``) are denied every
    action. A role with ``event_permission = Permitted()`` bypasses this
    policy entirely (handled by :class:`Permitted`).
    """

    def to_search_filter(
        self,
        user_id: uuid.UUID | None,
        action: Action,
        groups: frozenset[uuid.UUID] = frozenset(),
    ) -> SearchFilter[Any]:
        _ = groups  # the event scope does not depend on group membership
        if user_id is None:
            return NoneSearchFilter[Any]()
        if action in (Action.SEARCH, Action.READ):
            return EventAccessFilter[Any](user_id=user_id)
        return NoneSearchFilter[Any]()
