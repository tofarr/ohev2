"""Unit tests for the secret permission policy and its search filter.

With the link tables removed, secret access is governed by the generic
:class:`ACLPermission` (or :class:`Permitted` / :class:`Denied`) stored in
the role's ``secret_permission`` JSONB column. These tests verify the
reduction of those policies to :class:`SearchFilter` instances.
"""

from __future__ import annotations

import uuid

from openhands.ev2.security.security_models import (
    AclFilter,
    ACLPermission,
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

    def test_acl_permission_read_yields_acl_filter(self) -> None:
        sid = uuid.uuid4()
        policy = ACLPermission(permitted_ids={Action.READ: [sid]})
        filt = policy.to_search_filter(uuid.uuid4(), Action.READ)
        assert isinstance(filt, AclFilter)
        assert sid in filt.ids

    def test_acl_permission_empty_ids_yields_none_filter(self) -> None:
        policy = ACLPermission(permitted_ids={})
        filt = policy.to_search_filter(uuid.uuid4(), Action.READ)
        assert isinstance(filt, NoneSearchFilter)

    def test_acl_permission_missing_action_yields_none_filter(self) -> None:
        sid = uuid.uuid4()
        policy = ACLPermission(permitted_ids={Action.READ: [sid]})
        filt = policy.to_search_filter(uuid.uuid4(), Action.UPDATE)
        assert isinstance(filt, NoneSearchFilter)

    def test_acl_permission_create_yields_none_filter(self) -> None:
        # CREATE requires an explicit id list; an empty one denies.
        policy = ACLPermission(permitted_ids={})
        filt = policy.to_search_filter(uuid.uuid4(), Action.CREATE)
        assert isinstance(filt, NoneSearchFilter)
