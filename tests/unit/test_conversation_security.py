"""Unit tests for the conversation permission policy (ConversationAccess)."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

from openhands.ev2.conversation.conversation_security import (
    ConversationAccess,
    ConversationAccessFilter,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import NoneSearchFilter

_USER_ID = uuid.UUID("12345678-1234-5678-1234-456789abcdef")
_OTHER_ID = uuid.UUID("87654321-4321-8765-4321-fedcba987654")


def _conversation_with_owner(creator_id: uuid.UUID) -> SimpleNamespace:
    return SimpleNamespace(sandbox_config=SimpleNamespace(creator_id=creator_id))


class TestConversationAccessPolicy:
    def test_search_grants_scoped_filter(self) -> None:
        filt = ConversationAccess().to_search_filter(_USER_ID, Action.SEARCH)
        assert isinstance(filt, ConversationAccessFilter)
        assert filt.user_id == _USER_ID

    def test_read_grants_scoped_filter(self) -> None:
        filt = ConversationAccess().to_search_filter(_USER_ID, Action.READ)
        assert isinstance(filt, ConversationAccessFilter)
        assert filt.user_id == _USER_ID

    def test_write_actions_denied(self) -> None:
        policy = ConversationAccess()
        for action in (Action.CREATE, Action.UPDATE, Action.DELETE):
            filt = policy.to_search_filter(_USER_ID, action)
            assert isinstance(filt, NoneSearchFilter), f"{action} must be denied"

    def test_anonymous_denied_every_action(self) -> None:
        policy = ConversationAccess()
        for action in (Action.SEARCH, Action.READ, Action.CREATE, Action.UPDATE, Action.DELETE):
            filt = policy.to_search_filter(None, action)
            assert isinstance(filt, NoneSearchFilter), f"{action} must be denied anonymously"


class TestConversationAccessFilter:
    def test_matches_own_sandbox_config(self) -> None:
        filt = ConversationAccessFilter[SimpleNamespace](user_id=_USER_ID)
        assert filt.matches(_conversation_with_owner(_USER_ID)) is True

    def test_matches_rejects_other_owner(self) -> None:
        filt = ConversationAccessFilter[SimpleNamespace](user_id=_USER_ID)
        assert filt.matches(_conversation_with_owner(_OTHER_ID)) is False

    def test_matches_denies_when_relationship_unloaded(self) -> None:
        # The in-memory path is fail-closed: without the sandbox_config
        # relationship loaded, ownership cannot be established.
        filt = ConversationAccessFilter[SimpleNamespace](user_id=_USER_ID)
        assert filt.matches(SimpleNamespace(sandbox_config=None)) is False

    def test_sql_condition_scopes_via_sandbox_configs_subquery(self) -> None:
        filt = ConversationAccessFilter[SimpleNamespace](user_id=_USER_ID)
        condition = filt.sql_condition()
        assert condition is not None
        compiled = str(condition.compile(compile_kwargs={"literal_binds": True}))
        assert "sandbox_configs" in compiled
        assert "creator_id" in compiled
