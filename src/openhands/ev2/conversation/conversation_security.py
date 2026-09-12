"""Permission policy and search filter for the conversation resource.

Conversations use a custom permission policy, :class:`ConversationAccess`,
that grants non-admin users **search and read only**, scoped by a cross-table
ownership rule: a conversation is in scope iff its ``sandbox_config_id``
resolves to a :class:`SandboxConfig` whose ``creator_id`` equals the current
user. All other actions (create / update / delete) are denied — conversations
are created and maintained by the sandbox ingestion path, not by end users.

This cannot reuse :class:`CreatorPermission`: that policy scopes on the
resource's own ``creator_id``, and ``Conversation`` has none — ownership
derives from the backing sandbox config, so the SQL condition joins through
``sandbox_configs``.

A role with ``conversation_permission = Permitted()`` (the seeded admin role)
bypasses this entirely and gets full access — handled by :class:`Permitted`,
not this policy, exactly as ``api_key_permission`` works.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.sql.elements import ColumnElement

from openhands.ev2.conversation.conversation_models import Conversation
from openhands.ev2.sandbox.sandbox_config_models import SandboxConfig
from openhands.ev2.security.security_models import Action, Permission
from openhands.ev2.util.search_filter import (
    NoneSearchFilter,
    SearchFilter,
    T,
)


class ConversationAccessFilter(SearchFilter[T]):
    """Filter admitting conversations backed by a sandbox config the principal created.

    Admits a :class:`Conversation` iff ``sandbox_configs.creator_id == user_id``
    for its ``sandbox_config_id``. Expressed both in-memory (via the eagerly
    loaded ``sandbox_config`` relationship) and in SQL (an ``IN`` subquery so
    collection endpoints push the scope into the DB rather than materializing
    rows). The SQL path is authoritative for collection endpoints; the
    in-memory path requires the relationship to be loaded and denies when it
    is not.
    """

    user_id: uuid.UUID

    def matches(self, item: T) -> bool:
        sandbox_config = getattr(item, "sandbox_config", None)
        return sandbox_config is not None and sandbox_config.creator_id == self.user_id

    def sql_condition(self) -> ColumnElement[bool] | None:
        return Conversation.sandbox_config_id.in_(
            select(SandboxConfig.id).where(SandboxConfig.creator_id == self.user_id)
        )


class ConversationAccess(Permission):
    """Read/search-only policy scoped to conversations on the principal's sandbox configs.

    ``SEARCH`` and ``READ`` reduce to :class:`ConversationAccessFilter`;
    ``CREATE``, ``UPDATE``, and ``DELETE`` reduce to :class:`NoneSearchFilter`
    (deny). Anonymous principals (``user_id is None``) are denied every action.
    A role with ``conversation_permission = Permitted()`` bypasses this policy
    entirely (handled by :class:`Permitted`).
    """

    def to_search_filter(
        self,
        user_id: uuid.UUID | None,
        action: Action,
        groups: frozenset[uuid.UUID] = frozenset(),
    ) -> SearchFilter[Any]:
        _ = groups  # the conversation scope does not depend on group membership
        if user_id is None:
            return NoneSearchFilter[Any]()
        if action in (Action.SEARCH, Action.READ):
            return ConversationAccessFilter[Any](user_id=user_id)
        return NoneSearchFilter[Any]()
