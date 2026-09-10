"""Unit tests for the secret permission policy and its search filter.

With the link tables removed, secret access is governed by the generic
:class:`AclPermission` (or :class:`Permitted` / :class:`Denied`) stored in
the role's ``secret_permission`` JSONB column. These tests verify the
reduction of those policies to :class:`SearchFilter` instances.
"""

from __future__ import annotations

import uuid

from openhands.ev2.security.security_models import (
    AclPermission,
    Action,
    Denied,
    Permitted,
)
from openhands.ev2.util.search_filter import AllSearchFilter, NoneSearchFilter


class TestSecretPermissionReduction:
    def test_permitted_yields_all_filter_for_every_action(self) -> None:
        for action in (Action.READ, Action.UPDATE, Action.DELETE, Action.SEARCH, Action.CREATE):
            assert isinstance(Permitted().to_search_filter(uuid.uuid4(), action), AllSearchFilter)

    def test_denied_yields_none_filter_for_every_action(self) -> None:
        for action in (Action.READ, Action.UPDATE, Action.DELETE, Action.SEARCH, Action.CREATE):
            assert isinstance(Denied().to_search_filter(uuid.uuid4(), action), NoneSearchFilter)

    def test_acl_permission_read_admits_listed_secret(self) -> None:
        sid = uuid.uuid4()
        policy = AclPermission(item_ids=[sid], on_match=Permitted())
        filt = policy.to_search_filter(uuid.uuid4(), Action.READ)
        assert filt.matches(type("S", (), {"id": sid})())

    def test_acl_permission_empty_ids_denies_read_by_default(self) -> None:
        policy = AclPermission()
        filt = policy.to_search_filter(uuid.uuid4(), Action.READ)
        assert isinstance(filt, NoneSearchFilter)

    def test_acl_permission_missing_on_match_denies_listed(self) -> None:
        sid = uuid.uuid4()
        policy = AclPermission(item_ids=[sid])  # on_match defaults to Denied
        filt = policy.to_search_filter(uuid.uuid4(), Action.READ)
        assert not filt.matches(type("S", (), {"id": sid})())

    def test_acl_permission_create_denied_by_default(self) -> None:
        policy = AclPermission(item_ids=[uuid.uuid4()], on_match=Permitted())
        filt = policy.to_search_filter(uuid.uuid4(), Action.CREATE)
        assert isinstance(filt, NoneSearchFilter)
