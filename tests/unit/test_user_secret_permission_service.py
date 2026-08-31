"""Unit tests for UserSecretPermissionService (grant link-table CRUD, DB-backed)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.secret.secret_models import Secret
from openhands.ev2.secret.user_secret_permission_schemas import (
    UserSecretPermissionSearchFilter,
    UserSecretPermissionUpdate,
)
from openhands.ev2.secret.user_secret_permission_service import (
    UserSecretPermissionConflictError,
    UserSecretPermissionNotFoundError,
    UserSecretPermissionOrphanError,
    UserSecretPermissionService,
)
from openhands.ev2.user.user_models import User


@pytest.fixture
def service(session: AsyncSession) -> UserSecretPermissionService:
    return UserSecretPermissionService(session)


async def _seed_user_secret_permission(session: AsyncSession, *, n: int = 0) -> tuple[User, Secret]:
    user = User(email=f"usp{n}-{uuid.uuid4().hex[:4]}@example.com", username=f"usp{n}")
    secret = Secret(code=f"USP_{n}_{uuid.uuid4().hex[:6]}", value="v")
    session.add(user)
    session.add(secret)
    await session.flush()
    return user, secret


class TestCreateGrant:
    async def test_create_defaults(
        self, service: UserSecretPermissionService, session: AsyncSession
    ) -> None:
        user, secret = await _seed_user_secret_permission(session)
        link = await service.create(user_id=user.id, secret_id=secret.id)
        assert isinstance(link.id, uuid.UUID)
        assert link.user_id == user.id
        assert link.secret_id == secret.id
        assert link.read_enabled is False
        assert link.update_enabled is False
        assert link.delete_enabled is False

    async def test_create_with_flags(
        self, service: UserSecretPermissionService, session: AsyncSession
    ) -> None:
        user, secret = await _seed_user_secret_permission(session)
        link = await service.create(
            user_id=user.id, secret_id=secret.id, read_enabled=True, delete_enabled=True
        )
        assert link.read_enabled is True
        assert link.delete_enabled is True
        assert link.update_enabled is False

    async def test_create_duplicate_pair_conflicts(
        self, service: UserSecretPermissionService, session: AsyncSession
    ) -> None:
        user, secret = await _seed_user_secret_permission(session)
        await service.create(user_id=user.id, secret_id=secret.id)
        with pytest.raises(UserSecretPermissionConflictError):
            await service.create(user_id=user.id, secret_id=secret.id)

    async def test_create_orphan_user_raises(
        self, service: UserSecretPermissionService, session: AsyncSession
    ) -> None:
        _, secret = await _seed_user_secret_permission(session)
        with pytest.raises(UserSecretPermissionOrphanError):
            await service.create(user_id=uuid.uuid4(), secret_id=secret.id)

    async def test_create_orphan_secret_raises(
        self, service: UserSecretPermissionService, session: AsyncSession
    ) -> None:
        user, _ = await _seed_user_secret_permission(session)
        with pytest.raises(UserSecretPermissionOrphanError):
            await service.create(user_id=user.id, secret_id=uuid.uuid4())


class TestUpdateGrant:
    async def test_update_toggles_flags(
        self, service: UserSecretPermissionService, session: AsyncSession
    ) -> None:
        user, secret = await _seed_user_secret_permission(session)
        link = await service.create(user_id=user.id, secret_id=secret.id)
        updated = await service.update(
            link.id, UserSecretPermissionUpdate(read_enabled=True, update_enabled=True)
        )
        assert updated.read_enabled is True
        assert updated.update_enabled is True
        assert updated.delete_enabled is False

    async def test_update_missing_raises(self, service: UserSecretPermissionService) -> None:
        with pytest.raises(UserSecretPermissionNotFoundError):
            await service.update(uuid.uuid4(), UserSecretPermissionUpdate(read_enabled=True))


class TestDeleteGrant:
    async def test_delete_removes(
        self, service: UserSecretPermissionService, session: AsyncSession
    ) -> None:
        user, secret = await _seed_user_secret_permission(session)
        link = await service.create(user_id=user.id, secret_id=secret.id)
        await service.delete(link.id)
        with pytest.raises(UserSecretPermissionNotFoundError):
            await service.get(link.id)

    async def test_delete_missing_raises(self, service: UserSecretPermissionService) -> None:
        with pytest.raises(UserSecretPermissionNotFoundError):
            await service.delete(uuid.uuid4())


class TestSearchGrant:
    async def test_search_filters_by_user(
        self, service: UserSecretPermissionService, session: AsyncSession
    ) -> None:
        user, secret = await _seed_user_secret_permission(session)
        await service.create(user_id=user.id, secret_id=secret.id, read_enabled=True)
        links, _ = await service.search_user_secret_permissions(
            search_filter=UserSecretPermissionSearchFilter(user_id__eq=user.id)
        )
        assert len(links) == 1
        assert links[0].read_enabled is True

    async def test_count(self, service: UserSecretPermissionService, session: AsyncSession) -> None:
        user, secret = await _seed_user_secret_permission(session)
        await service.create(user_id=user.id, secret_id=secret.id)
        assert await service.count() >= 1
