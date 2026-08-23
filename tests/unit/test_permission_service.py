"""Unit tests for the permission service (DB-backed)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from ohev.permission.models.permission import Action, SelectorKind
from ohev.permission.schemas import PermissionCreate, PermissionUpdate
from ohev.permission.services import (
    PermissionNotFoundError,
    PermissionService,
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
        "resource_type": "users",
        "selector_kind": SelectorKind.ALL,
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
        assert perm.resource_type == "users"
        assert perm.selector_kind is SelectorKind.ALL
        assert perm.created_at is not None

    async def test_create_with_attributes(self, service: PermissionService, session) -> None:
        uid = await _make_user(session)
        perm = await service.create(_create_payload(uid, attributes=["email", "name"]))
        assert perm.attributes == ["email", "name"]

    async def test_create_by_id_selector(self, service: PermissionService, session) -> None:
        uid = await _make_user(session)
        perm = await service.create(
            _create_payload(
                uid,
                selector_kind=SelectorKind.BY_ID,
                selector_value="abc-123",
            )
        )
        assert perm.selector_kind is SelectorKind.BY_ID
        assert perm.selector_value == "abc-123"

    async def test_create_custom_action(self, service: PermissionService, session) -> None:
        uid = await _make_user(session)
        perm = await service.create(
            _create_payload(
                uid, action=Action.USE, custom_action="deploy", resource_type="sandboxes"
            )
        )
        assert perm.action is Action.USE
        assert perm.custom_action == "deploy"


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
    async def test_list_empty(self, service: PermissionService) -> None:
        perms, next_cursor = await service.list_permissions()
        assert perms == []
        assert next_cursor is None

    async def test_list_filtered_by_user(self, service: PermissionService, session) -> None:
        uid1 = await _make_user(session, email="first@example.com")
        uid2 = await _make_user(session, email="second@example.com")

        await service.create(_create_payload(uid1, resource_type="users"))
        await service.create(_create_payload(uid1, resource_type="sandboxes"))
        await service.create(_create_payload(uid2, resource_type="users"))

        perms, _ = await service.list_permissions(user_id=uid1)
        assert len(perms) == 2
        assert all(p.user_id == uid1 for p in perms)

    async def test_list_pagination(self, service: PermissionService, session) -> None:
        uid = await _make_user(session)
        for rt in ["a", "b", "c", "d", "e"]:
            await service.create(_create_payload(uid, resource_type=rt))
        perms, next_cursor = await service.list_permissions(limit=2)
        assert len(perms) == 2
        assert next_cursor is not None
        perms2, next_cursor2 = await service.list_permissions(cursor=next_cursor, limit=2)
        assert len(perms2) == 2
        perms3, next_cursor3 = await service.list_permissions(cursor=next_cursor2, limit=2)
        assert len(perms3) == 1
        assert next_cursor3 is None


class TestUpdatePermission:
    async def test_update_action(self, service: PermissionService, session) -> None:
        uid = await _make_user(session)
        perm = await service.create(_create_payload(uid))
        updated = await service.update(perm.id, PermissionUpdate(action=Action.WRITE))
        assert updated.action is Action.WRITE

    async def test_update_attributes(self, service: PermissionService, session) -> None:
        uid = await _make_user(session)
        perm = await service.create(_create_payload(uid))
        updated = await service.update(perm.id, PermissionUpdate(attributes=["email"]))
        assert updated.attributes == ["email"]

    async def test_update_missing_raises(self, service: PermissionService) -> None:
        with pytest.raises(PermissionNotFoundError):
            await service.update(uuid.uuid4(), PermissionUpdate(action=Action.WRITE))


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
        await service.create(_create_payload(uid, resource_type="users"))
        await service.create(_create_payload(uid, resource_type="sandboxes"))
        perms = await service.list_for_user(uid)
        assert len(perms) == 2

    async def test_empty_for_user_with_none(self, service: PermissionService, session) -> None:
        uid = await _make_user(session)
        perms = await service.list_for_user(uid)
        assert perms == []


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
