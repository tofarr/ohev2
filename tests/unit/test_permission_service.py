"""Unit tests for the permission service (DB-backed)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from ohev.permission.models.permission import Action, ResourceType
from ohev.permission.schemas import PermissionCreate
from ohev.permission.services import (
    PermissionNotFoundError,
    PermissionService,
    reset_base_permissions_cache,
)
from ohev.user.schemas import UserCreate
from ohev.user.services import UserService


async def _make_user(session: AsyncSession, email: str = "perm-test@example.com") -> uuid.UUID:
    user = await UserService(session).create(UserCreate(email=email))
    return user.id


@pytest.fixture
def service(session: AsyncSession) -> PermissionService:
    return PermissionService(session)


def _create_payload(user_id: uuid.UUID, **overrides) -> PermissionCreate:
    defaults = {
        "user_id": user_id,
        "action": Action.READ,
        "type": ResourceType.USER,
    }
    defaults.update(overrides)
    return PermissionCreate(**defaults)


class TestCreatePermission:
    async def test_create_permission(self, service: PermissionService, session) -> None:
        uid = await _make_user(session)
        perm = await service.create(_create_payload(uid))
        assert perm.id is not None
        assert perm.user_id == uid
        assert perm.action is Action.READ
        assert perm.type is ResourceType.USER
        assert perm.created_at is not None

    async def test_create_with_attributes(self, service: PermissionService, session) -> None:
        uid = await _make_user(session)
        perm = await service.create(_create_payload(uid, attributes=["email", "name"]))
        assert perm.attributes == ["email", "name"]

    async def test_create_permission_type(self, service: PermissionService, session) -> None:
        uid = await _make_user(session)
        perm = await service.create(_create_payload(uid, type=ResourceType.PERMISSION))
        assert perm.type is ResourceType.PERMISSION

    async def test_create_all_action(self, service: PermissionService, session) -> None:
        uid = await _make_user(session)
        perm = await service.create(_create_payload(uid, action=Action.ALL))
        assert perm.action is Action.ALL


class TestGetPermission:
    async def test_get_existing(self, service: PermissionService, session) -> None:
        uid = await _make_user(session)
        created = await service.create(_create_payload(uid))
        fetched = await service.get(created.id)
        assert fetched.id == created.id

    async def test_get_missing_raises(self, service: PermissionService) -> None:
        with pytest.raises(PermissionNotFoundError):
            await service.get(uuid.uuid4())


class TestListPermissions:
    async def test_search_empty(self, service: PermissionService) -> None:
        perms, next_cursor = await service.search_permissions()
        assert perms == []
        assert next_cursor is None

    async def test_search_filtered_by_user(self, service: PermissionService, session) -> None:
        uid1 = await _make_user(session, email="first@example.com")
        uid2 = await _make_user(session, email="second@example.com")

        await service.create(_create_payload(uid1, type=ResourceType.USER))
        await service.create(_create_payload(uid1, type=ResourceType.PERMISSION))
        await service.create(_create_payload(uid2, type=ResourceType.USER))

        perms, _ = await service.search_permissions(user_id=uid1)
        assert len(perms) == 2
        assert all(p.user_id == uid1 for p in perms)

    async def test_search_pagination(self, service: PermissionService, session) -> None:
        uid = await _make_user(session)
        for act in [Action.CREATE, Action.READ, Action.UPDATE, Action.DELETE, Action.SEARCH]:
            await service.create(_create_payload(uid, action=act))
        perms, next_cursor = await service.search_permissions(limit=2)
        assert len(perms) == 2
        assert next_cursor is not None
        perms2, next_cursor2 = await service.search_permissions(cursor=next_cursor, limit=2)
        assert len(perms2) == 2
        perms3, next_cursor3 = await service.search_permissions(cursor=next_cursor2, limit=2)
        assert len(perms3) == 1
        assert next_cursor3 is None


class TestDeletePermission:
    async def test_delete_permission(self, service: PermissionService, session) -> None:
        uid = await _make_user(session)
        perm = await service.create(_create_payload(uid))
        await service.delete(perm.id)
        with pytest.raises(PermissionNotFoundError):
            await service.get(perm.id)

    async def test_delete_missing_raises(self, service: PermissionService) -> None:
        with pytest.raises(PermissionNotFoundError):
            await service.delete(uuid.uuid4())


class TestListForUser:
    async def test_returns_all_user_permissions(self, service: PermissionService, session) -> None:
        uid = await _make_user(session)
        await service.create(_create_payload(uid, type=ResourceType.USER))
        await service.create(_create_payload(uid, type=ResourceType.PERMISSION))
        perms = await service.search_for_user(uid)
        assert len(perms) == 2

    async def test_empty_for_user_with_none(self, service: PermissionService, session) -> None:
        uid = await _make_user(session)
        perms = await service.search_for_user(uid)
        assert perms == []


class TestCheckPermission:
    """Tests for the single-SQL-query permission check."""

    async def test_base_grant_allows_without_db_row(
        self, service: PermissionService, session
    ) -> None:
        """Config baseline grants all on user/permission — no DB row needed."""
        uid = await _make_user(session)
        assert await service.check_permission(uid, Action.READ, ResourceType.USER)
        assert await service.check_permission(uid, Action.CREATE, ResourceType.PERMISSION)
        assert await service.check_permission(uid, Action.DELETE, ResourceType.USER)

    async def test_db_grant_allows_when_base_denies(
        self, service: PermissionService, session, monkeypatch
    ) -> None:
        """With an empty baseline, a DB permission row grants the request."""
        from ohev.config import get_config

        get_config.cache_clear()
        reset_base_permissions_cache()
        monkeypatch.delenv("OHEV_BASE_PERMISSIONS_0", raising=False)
        monkeypatch.delenv("OHEV_BASE_PERMISSIONS_1", raising=False)
        monkeypatch.setenv("OHEV_BASE_PERMISSIONS_0", "")

        uid = await _make_user(session)
        await service.create(_create_payload(uid, action=Action.READ, type=ResourceType.PERMISSION))
        assert await service.check_permission(uid, Action.READ, ResourceType.PERMISSION)
        assert not await service.check_permission(uid, Action.CREATE, ResourceType.PERMISSION)

    async def test_all_action_grants_any(self, service: PermissionService, session) -> None:
        """An ALL-action permission covers any specific action via the DB path."""
        uid = await _make_user(session)
        await service.create(_create_payload(uid, action=Action.ALL, type=ResourceType.USER))
        # Base grants already allow these; the DB ALL row also returns True.
        assert await service.check_permission(uid, Action.READ, ResourceType.USER)
        assert await service.check_permission(uid, Action.DELETE, ResourceType.USER)

    async def test_wrong_type_denied_via_db(
        self, service: PermissionService, session, monkeypatch
    ) -> None:
        """A permission for USER does not grant access to PERMISSION."""
        from ohev.config import get_config

        get_config.cache_clear()
        reset_base_permissions_cache()
        monkeypatch.delenv("OHEV_BASE_PERMISSIONS_0", raising=False)
        monkeypatch.delenv("OHEV_BASE_PERMISSIONS_1", raising=False)
        monkeypatch.setenv("OHEV_BASE_PERMISSIONS_0", "")

        uid = await _make_user(session)
        await service.create(_create_payload(uid, action=Action.ALL, type=ResourceType.USER))
        assert not await service.check_permission(uid, Action.READ, ResourceType.PERMISSION)

    async def test_attribute_subset_denies_unlisted(
        self, service: PermissionService, session, monkeypatch
    ) -> None:
        """A permission with attributes subset denies unlisted attributes."""
        from ohev.config import get_config

        get_config.cache_clear()
        reset_base_permissions_cache()
        monkeypatch.delenv("OHEV_BASE_PERMISSIONS_0", raising=False)
        monkeypatch.delenv("OHEV_BASE_PERMISSIONS_1", raising=False)
        monkeypatch.setenv("OHEV_BASE_PERMISSIONS_0", "")

        uid = await _make_user(session)
        await service.create(
            _create_payload(
                uid,
                action=Action.READ,
                type=ResourceType.USER,
                attributes=["email"],
            )
        )
        assert await service.check_permission(
            uid, Action.READ, ResourceType.USER, attributes=("email",)
        )
        assert not await service.check_permission(
            uid, Action.READ, ResourceType.USER, attributes=("email", "password")
        )

    async def test_no_permission_denied(
        self, service: PermissionService, session, monkeypatch
    ) -> None:
        """With empty baseline and no DB row, access is denied."""
        from ohev.config import get_config

        get_config.cache_clear()
        reset_base_permissions_cache()
        monkeypatch.delenv("OHEV_BASE_PERMISSIONS_0", raising=False)
        monkeypatch.delenv("OHEV_BASE_PERMISSIONS_1", raising=False)
        monkeypatch.setenv("OHEV_BASE_PERMISSIONS_0", "")

        uid = await _make_user(session)
        assert not await service.check_permission(uid, Action.READ, ResourceType.USER)


class TestCascadeDelete:
    async def test_deleting_user_cascades_to_permissions(self, session) -> None:
        from ohev.user.services import UserService

        uid = await _make_user(session)
        ps = PermissionService(session)
        await ps.create(_create_payload(uid))
        assert await ps.count() == 1

        await UserService(session).delete(uid)
        await session.commit()
        assert await ps.count() == 0
