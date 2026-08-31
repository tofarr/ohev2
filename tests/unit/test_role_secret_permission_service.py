"""Unit tests for the RoleSecretPermissionService (grant link-table CRUD, DB-backed)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.role.role_models import Role
from openhands.ev2.secret.role_secret_permission_schemas import RoleSecretPermissionUpdate
from openhands.ev2.secret.role_secret_permission_service import (
    RoleSecretPermissionConflictError,
    RoleSecretPermissionNotFoundError,
    RoleSecretPermissionOrphanError,
    RoleSecretPermissionService,
)
from openhands.ev2.secret.secret_models import Secret
from openhands.ev2.user.user_models import User


@pytest.fixture
def service(session: AsyncSession) -> RoleSecretPermissionService:
    return RoleSecretPermissionService(session)


async def _seed_role_secret_permission_user(
    session: AsyncSession, *, n: int = 0
) -> tuple[Role, Secret, User]:
    user = User(email=f"rs{n}@example.com", username=f"rsu{n}")
    role = Role(name=f"rs-role-{n}-{uuid.uuid4().hex[:4]}")
    session.add(user)
    session.add(role)
    await session.flush()
    secret = Secret(code=f"RS_{n}_{uuid.uuid4().hex[:6]}", value="v")
    session.add(secret)
    await session.flush()
    return role, secret, user


class TestCreateGrant:
    async def test_create_defaults(
        self, service: RoleSecretPermissionService, session: AsyncSession
    ) -> None:
        role, secret, _ = await _seed_role_secret_permission_user(session)
        link = await service.create(role_id=role.id, secret_id=secret.id)
        assert isinstance(link.id, uuid.UUID)
        assert link.role_id == role.id
        assert link.secret_id == secret.id
        assert link.read_enabled is False
        assert link.update_enabled is False
        assert link.delete_enabled is False

    async def test_create_with_flags(
        self, service: RoleSecretPermissionService, session: AsyncSession
    ) -> None:
        role, secret, _ = await _seed_role_secret_permission_user(session)
        link = await service.create(
            role_id=role.id, secret_id=secret.id, read_enabled=True, delete_enabled=True
        )
        assert link.read_enabled is True
        assert link.delete_enabled is True
        assert link.update_enabled is False

    async def test_create_duplicate_pair_conflicts(
        self, service: RoleSecretPermissionService, session: AsyncSession
    ) -> None:
        role, secret, _ = await _seed_role_secret_permission_user(session)
        await service.create(role_id=role.id, secret_id=secret.id)
        with pytest.raises(RoleSecretPermissionConflictError):
            await service.create(role_id=role.id, secret_id=secret.id)

    async def test_create_orphan_role_raises(
        self, service: RoleSecretPermissionService, session: AsyncSession
    ) -> None:
        _, secret, _ = await _seed_role_secret_permission_user(session)
        with pytest.raises(RoleSecretPermissionOrphanError):
            await service.create(role_id=uuid.uuid4(), secret_id=secret.id)

    async def test_create_orphan_secret_raises(
        self, service: RoleSecretPermissionService, session: AsyncSession
    ) -> None:
        role, _, _ = await _seed_role_secret_permission_user(session)
        with pytest.raises(RoleSecretPermissionOrphanError):
            await service.create(role_id=role.id, secret_id=uuid.uuid4())


class TestUpdateGrant:
    async def test_update_toggles_flags(
        self, service: RoleSecretPermissionService, session: AsyncSession
    ) -> None:
        role, secret, _ = await _seed_role_secret_permission_user(session)
        link = await service.create(role_id=role.id, secret_id=secret.id)
        updated = await service.update(
            link.id, RoleSecretPermissionUpdate(read_enabled=True, update_enabled=True)
        )
        assert updated.read_enabled is True
        assert updated.update_enabled is True
        assert updated.delete_enabled is False

    async def test_update_missing_raises(self, service: RoleSecretPermissionService) -> None:
        with pytest.raises(RoleSecretPermissionNotFoundError):
            await service.update(uuid.uuid4(), RoleSecretPermissionUpdate(read_enabled=True))


class TestDeleteGrant:
    async def test_delete_removes(
        self, service: RoleSecretPermissionService, session: AsyncSession
    ) -> None:
        role, secret, _ = await _seed_role_secret_permission_user(session)
        link = await service.create(role_id=role.id, secret_id=secret.id)
        await service.delete(link.id)
        with pytest.raises(RoleSecretPermissionNotFoundError):
            await service.get(link.id)

    async def test_delete_missing_raises(self, service: RoleSecretPermissionService) -> None:
        with pytest.raises(RoleSecretPermissionNotFoundError):
            await service.delete(uuid.uuid4())


class TestSearchGrant:
    async def test_search_filters_by_role(
        self, service: RoleSecretPermissionService, session: AsyncSession
    ) -> None:
        role, secret, _ = await _seed_role_secret_permission_user(session)
        await service.create(role_id=role.id, secret_id=secret.id, read_enabled=True)
        from openhands.ev2.secret.role_secret_permission_schemas import (
            RoleSecretPermissionSearchFilter,
        )

        links, _ = await service.search_role_secret_permissions(
            search_filter=RoleSecretPermissionSearchFilter(role_id__eq=role.id)
        )
        assert len(links) == 1
        assert links[0].read_enabled is True

    async def test_count(self, service: RoleSecretPermissionService, session: AsyncSession) -> None:
        role, secret, _ = await _seed_role_secret_permission_user(session)
        await service.create(role_id=role.id, secret_id=secret.id)
        assert await service.count() >= 1
