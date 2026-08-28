"""Unit tests for the role-user assignment service (DB-backed)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.role.role_user_schemas import RoleUserSearchFilter
from openhands.ev2.role.role_user_service import (
    RoleUserConflictError,
    RoleUserNotFoundError,
    RoleUserOrphanError,
    RoleUserService,
)
from openhands.ev2.security.security_models import Role
from openhands.ev2.user.user_models import User


@pytest.fixture
def service(session: AsyncSession) -> RoleUserService:
    return RoleUserService(session)


async def _seed_role_and_user(
    session: AsyncSession,
    *,
    role_name: str = "test-role",
    email: str = "ru@example.com",
    username: str = "ru",
) -> tuple[Role, User]:
    role = Role(name=role_name)
    user = User(email=email, username=username)
    session.add(role)
    session.add(user)
    await session.flush()
    return role, user


class TestCreateAssignment:
    async def test_create_assignment(self, service: RoleUserService, session: AsyncSession) -> None:
        role, user = await _seed_role_and_user(session)
        link = await service.create(role.id, user.id)
        assert isinstance(link.id, uuid.UUID)
        assert link.role_id == role.id
        assert link.user_id == user.id
        assert link.created_at is not None

    async def test_create_duplicate_conflicts(
        self, service: RoleUserService, session: AsyncSession
    ) -> None:
        role, user = await _seed_role_and_user(session)
        await service.create(role.id, user.id)
        with pytest.raises(RoleUserConflictError):
            await service.create(role.id, user.id)

    async def test_create_missing_role_raises(
        self, service: RoleUserService, session: AsyncSession
    ) -> None:
        _role, user = await _seed_role_and_user(session)
        with pytest.raises((RoleUserOrphanError, Exception)):
            await service.create(uuid.uuid4(), user.id)


class TestGetAssignment:
    async def test_get_existing(self, service: RoleUserService, session: AsyncSession) -> None:
        role, user = await _seed_role_and_user(session)
        link = await service.create(role.id, user.id)
        fetched = await service.get(link.id)
        assert fetched.id == link.id

    async def test_get_missing_raises(self, service: RoleUserService) -> None:
        with pytest.raises(RoleUserNotFoundError):
            await service.get(uuid.uuid4())


class TestSearchAssignments:
    async def test_search_empty(self, service: RoleUserService) -> None:
        links, next_cursor = await service.search_role_users()
        assert links == []
        assert next_cursor is None

    async def test_search_returns_assignments(
        self, service: RoleUserService, session: AsyncSession
    ) -> None:
        role, user = await _seed_role_and_user(session)
        await service.create(role.id, user.id)
        links, next_cursor = await service.search_role_users()
        assert len(links) == 1
        assert next_cursor is None

    async def test_search_pagination_with_limit(
        self, service: RoleUserService, session: AsyncSession
    ) -> None:
        role = Role(name="multi")
        session.add(role)
        await session.flush()
        for i in range(5):
            u = User(email=f"u{i}@example.com", username=f"u{i}")
            session.add(u)
            await session.flush()
            await service.create(role.id, u.id)
        links, next_cursor = await service.search_role_users(limit=2)
        assert len(links) == 2
        assert next_cursor is not None

        links2, next_cursor2 = await service.search_role_users(cursor=next_cursor, limit=2)
        assert len(links2) == 2
        assert next_cursor2 is not None

        links3, next_cursor3 = await service.search_role_users(cursor=next_cursor2, limit=2)
        assert len(links3) == 1
        assert next_cursor3 is None

    async def test_search_role_id_filter(
        self, service: RoleUserService, session: AsyncSession
    ) -> None:
        role_a = Role(name="a")
        role_b = Role(name="b")
        user = User(email="u@example.com", username="u")
        session.add(role_a)
        session.add(role_b)
        session.add(user)
        await session.flush()
        await service.create(role_a.id, user.id)
        await service.create(role_b.id, user.id)
        links, _ = await service.search_role_users(
            search_filter=RoleUserSearchFilter(role_id__eq=role_a.id)
        )
        assert len(links) == 1
        assert links[0].role_id == role_a.id

    async def test_search_user_id_filter(
        self, service: RoleUserService, session: AsyncSession
    ) -> None:
        role = Role(name="r")
        user_a = User(email="a@example.com", username="a")
        user_b = User(email="b@example.com", username="b")
        session.add(role)
        session.add(user_a)
        session.add(user_b)
        await session.flush()
        await service.create(role.id, user_a.id)
        await service.create(role.id, user_b.id)
        links, _ = await service.search_role_users(
            search_filter=RoleUserSearchFilter(user_id__eq=user_b.id)
        )
        assert len(links) == 1
        assert links[0].user_id == user_b.id


class TestCountAssignments:
    async def test_count_empty(self, service: RoleUserService) -> None:
        assert await service.count() == 0

    async def test_count_after_creates(
        self, service: RoleUserService, session: AsyncSession
    ) -> None:
        role, user = await _seed_role_and_user(session)
        await service.create(role.id, user.id)
        assert await service.count() == 1

    async def test_count_with_filter(self, service: RoleUserService, session: AsyncSession) -> None:
        role_a = Role(name="a")
        role_b = Role(name="b")
        user = User(email="u@example.com", username="u")
        session.add(role_a)
        session.add(role_b)
        session.add(user)
        await session.flush()
        await service.create(role_a.id, user.id)
        await service.create(role_b.id, user.id)
        assert await service.count(search_filter=RoleUserSearchFilter(role_id__eq=role_a.id)) == 1


class TestDeleteAssignment:
    async def test_delete_assignment(self, service: RoleUserService, session: AsyncSession) -> None:
        role, user = await _seed_role_and_user(session)
        link = await service.create(role.id, user.id)
        await service.delete(link.id)
        with pytest.raises(RoleUserNotFoundError):
            await service.get(link.id)

    async def test_delete_missing_raises(self, service: RoleUserService) -> None:
        with pytest.raises(RoleUserNotFoundError):
            await service.delete(uuid.uuid4())
