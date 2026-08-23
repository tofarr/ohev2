"""Unit tests for the user service (DB-backed)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from ohev.user.schemas import UserCreate, UserUpdate
from ohev.user.services import UserEmailConflictError, UserNotFoundError, UserService


@pytest.fixture
def service(session: AsyncSession) -> UserService:
    return UserService(session)


class TestCreateUser:
    async def test_create_user(self, service: UserService) -> None:
        user = await service.create(UserCreate(email="alice@example.com"))
        assert user.id is not None
        assert isinstance(user.id, uuid.UUID)
        assert user.email == "alice@example.com"
        assert user.created_at is not None
        assert user.updated_at is not None

    async def test_create_duplicate_email_conflicts(self, service: UserService) -> None:
        await service.create(UserCreate(email="alice@example.com"))
        with pytest.raises(UserEmailConflictError):
            await service.create(UserCreate(email="alice@example.com"))

    async def test_create_invalid_email_rejected_at_schema(self) -> None:
        with pytest.raises(ValueError):
            UserCreate(email="not-an-email")  # type: ignore[arg-type]


class TestGetUser:
    async def test_get_existing_user(self, service: UserService) -> None:
        created = await service.create(UserCreate(email="bob@example.com"))
        fetched = await service.get(created.id)
        assert fetched.id == created.id
        assert fetched.email == "bob@example.com"

    async def test_get_missing_user_raises(self, service: UserService) -> None:
        with pytest.raises(UserNotFoundError):
            await service.get(uuid.uuid4())


class TestListUsers:
    async def test_list_empty(self, service: UserService) -> None:
        users, next_cursor = await service.list_users()
        assert users == []
        assert next_cursor is None

    async def test_list_returns_users(self, service: UserService) -> None:
        await service.create(UserCreate(email="a@example.com"))
        await service.create(UserCreate(email="b@example.com"))
        users, next_cursor = await service.list_users()
        assert len(users) == 2
        assert next_cursor is None

    async def test_list_pagination_with_limit(self, service: UserService) -> None:
        for i in range(5):
            await service.create(UserCreate(email=f"u{i}@example.com"))
        users, next_cursor = await service.list_users(limit=2)
        assert len(users) == 2
        assert next_cursor is not None

        users2, next_cursor2 = await service.list_users(cursor=next_cursor, limit=2)
        assert len(users2) == 2
        assert next_cursor2 is not None

        users3, next_cursor3 = await service.list_users(cursor=next_cursor2, limit=2)
        assert len(users3) == 1
        assert next_cursor3 is None

    async def test_list_sorted_by_id(self, service: UserService) -> None:
        a = await service.create(UserCreate(email="a@example.com"))
        b = await service.create(UserCreate(email="b@example.com"))
        users, _ = await service.list_users()
        # List is ordered by id ascending; with random UUIDs the order is
        # deterministic but not insertion order.
        ids = [u.id for u in users]
        assert set(ids) == {a.id, b.id}
        assert ids == sorted(ids)


class TestUpdateUser:
    async def test_update_email(self, service: UserService) -> None:
        user = await service.create(UserCreate(email="old@example.com"))
        updated = await service.update(user.id, UserUpdate(email="new@example.com"))
        assert updated.email == "new@example.com"

    async def test_update_no_fields_keeps_email(self, service: UserService) -> None:
        user = await service.create(UserCreate(email="keep@example.com"))
        updated = await service.update(user.id, UserUpdate())
        assert updated.email == "keep@example.com"

    async def test_update_missing_user_raises(self, service: UserService) -> None:
        with pytest.raises(UserNotFoundError):
            await service.update(uuid.uuid4(), UserUpdate(email="x@example.com"))

    async def test_update_to_existing_email_conflicts(self, service: UserService) -> None:
        await service.create(UserCreate(email="taken@example.com"))
        user = await service.create(UserCreate(email="other@example.com"))
        with pytest.raises(UserEmailConflictError):
            await service.update(user.id, UserUpdate(email="taken@example.com"))


class TestDeleteUser:
    async def test_delete_user(self, service: UserService) -> None:
        user = await service.create(UserCreate(email="del@example.com"))
        await service.delete(user.id)
        with pytest.raises(UserNotFoundError):
            await service.get(user.id)

    async def test_delete_missing_user_raises(self, service: UserService) -> None:
        with pytest.raises(UserNotFoundError):
            await service.delete(uuid.uuid4())


class TestCount:
    async def test_count_empty(self, service: UserService) -> None:
        assert await service.count() == 0

    async def test_count_after_creates(self, service: UserService) -> None:
        await service.create(UserCreate(email="a@example.com"))
        await service.create(UserCreate(email="b@example.com"))
        assert await service.count() == 2
