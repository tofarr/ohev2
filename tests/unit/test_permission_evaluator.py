"""Unit tests for permission matching and the check_permission service method.

The model-level `matches_action` and `matches_attributes` methods are pure and
tested without a database. The `check_permission` service method is DB-backed
and tested via the session fixture.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.permission.permission_models import Action, Permission, ResourceType
from openhands.ev2.permission.permission_schemas import PermissionCreate
from openhands.ev2.permission.permission_service import (
    PermissionService,
    reset_base_permissions_cache,
)
from openhands.ev2.user.user_models import User
from openhands.ev2.user.user_schemas import UserCreate
from openhands.ev2.user.user_service import UserService
from openhands.ev2.util.search_filter import AllSearchFilter

# Unrestricted permission filter for service-level CRUD tests.
_ALL = AllSearchFilter[Permission]()


def _perm(
    *,
    action: Action = Action.READ,
    resource_type: ResourceType = ResourceType.USER,
    attributes: list[str] | None = None,
) -> Permission:
    return Permission(
        user_id=uuid.uuid4(),
        action=action,
        resource_type=resource_type,
        attributes=attributes,
    )


class TestActionMatching:
    def test_exact_action_match(self) -> None:
        assert _perm(action=Action.READ).matches_action("read")

    def test_wrong_action_denied(self) -> None:
        assert not _perm(action=Action.READ).matches_action("update")

    def test_wildcard_action_covers_all(self) -> None:
        perm = _perm(action=Action.ALL)
        assert perm.matches_action("read")
        assert perm.matches_action("update")
        assert perm.matches_action("delete")
        assert perm.matches_action("search")

    def test_search_action_matches(self) -> None:
        assert _perm(action=Action.SEARCH).matches_action("search")

    def test_use_action_matches(self) -> None:
        assert _perm(action=Action.USE).matches_action("use")


class TestAttributeMatching:
    def test_no_attribute_restriction_covers_all(self) -> None:
        perm = _perm()
        assert perm.matches_attributes(["email", "name"])

    def test_attribute_subset_covers_requested(self) -> None:
        perm = _perm(attributes=["email", "name"])
        assert perm.matches_attributes(["email"])

    def test_attribute_subset_denies_unlisted(self) -> None:
        perm = _perm(attributes=["email"])
        assert not perm.matches_attributes(["email", "password"])

    def test_empty_requested_attributes_allowed(self) -> None:
        perm = _perm(attributes=["email"])
        assert perm.matches_attributes([])


class TestCheckPermissionDB:
    """DB-backed tests for PermissionService.check_permission."""

    async def _make_user(
        self,
        session: AsyncSession,
        email: str = "check@example.com",
        username: str = "check",
    ) -> uuid.UUID:
        user = await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email=email, username=username)
        )
        return user.id

    async def test_base_grant_allows_without_db(self, session: AsyncSession) -> None:
        """Config baseline grants all on user/permission — no DB row needed."""
        service = PermissionService(session)
        uid = await self._make_user(session)
        assert await service.check_permission(uid, Action.READ, ResourceType.USER)
        assert await service.check_permission(uid, Action.CREATE, ResourceType.PERMISSION)

    async def test_db_grant_allows_when_base_empty(
        self, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With an empty baseline, a DB permission row grants the request."""
        from openhands.ev2.config import get_config

        get_config.cache_clear()
        reset_base_permissions_cache()
        monkeypatch.delenv("OHEV_BASE_PERMISSIONS_0", raising=False)
        monkeypatch.delenv("OHEV_BASE_PERMISSIONS_1", raising=False)
        monkeypatch.setenv("OHEV_BASE_PERMISSIONS_0", "")

        service = PermissionService(session, _ALL)
        uid = await self._make_user(session)
        await service.create(
            PermissionCreate(
                user_id=uid, action=Action.READ, resource_type=ResourceType.PERMISSION
            ),
        )
        assert await service.check_permission(uid, Action.READ, ResourceType.PERMISSION)
        assert not await service.check_permission(uid, Action.CREATE, ResourceType.PERMISSION)

    async def test_wrong_type_denied_via_db(
        self, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A permission for USER does not grant access to PERMISSION."""
        from openhands.ev2.config import get_config

        get_config.cache_clear()
        reset_base_permissions_cache()
        monkeypatch.delenv("OHEV_BASE_PERMISSIONS_0", raising=False)
        monkeypatch.delenv("OHEV_BASE_PERMISSIONS_1", raising=False)
        monkeypatch.setenv("OHEV_BASE_PERMISSIONS_0", "")

        service = PermissionService(session, _ALL)
        uid = await self._make_user(session)
        await service.create(
            PermissionCreate(user_id=uid, action=Action.ALL, resource_type=ResourceType.USER),
        )
        assert not await service.check_permission(uid, Action.READ, ResourceType.PERMISSION)

    async def test_deny_all_search_filter(
        self, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A permission with a None (deny-all) search filter still counts as a grant."""
        from openhands.ev2.config import get_config

        get_config.cache_clear()
        reset_base_permissions_cache()
        monkeypatch.delenv("OHEV_BASE_PERMISSIONS_0", raising=False)
        monkeypatch.delenv("OHEV_BASE_PERMISSIONS_1", raising=False)
        monkeypatch.setenv("OHEV_BASE_PERMISSIONS_0", "")

        service = PermissionService(session, _ALL)
        uid = await self._make_user(session)
        await service.create(
            PermissionCreate(
                user_id=uid,
                action=Action.READ,
                resource_type=ResourceType.USER,
                search_filter={"kind": "NoneSearchFilter"},
            ),
        )
        # A grant exists, so check_permission returns True; the deny-all scope
        # is enforced when the effective filter is applied to SQL.
        assert await service.check_permission(uid, Action.READ, ResourceType.USER)
        eff = await service.get_effective_filter(uid, Action.READ, ResourceType.USER)
        assert eff is not None

    async def test_no_permission_denied(
        self, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With empty baseline and no DB row, access is denied."""
        from openhands.ev2.config import get_config

        get_config.cache_clear()
        reset_base_permissions_cache()
        monkeypatch.delenv("OHEV_BASE_PERMISSIONS_0", raising=False)
        monkeypatch.delenv("OHEV_BASE_PERMISSIONS_1", raising=False)
        monkeypatch.setenv("OHEV_BASE_PERMISSIONS_0", "")

        service = PermissionService(session)
        uid = await self._make_user(session)
        assert not await service.check_permission(uid, Action.READ, ResourceType.USER)
