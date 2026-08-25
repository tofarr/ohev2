"""Unit tests for the user service (DB-backed)."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from ohev.user.schemas import UserCreate, UserSearchFilter, UserUpdate
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
    async def test_search_empty(self, service: UserService) -> None:
        users, next_cursor = await service.search_users()
        assert users == []
        assert next_cursor is None

    async def test_search_returns_users(self, service: UserService) -> None:
        await service.create(UserCreate(email="a@example.com"))
        await service.create(UserCreate(email="b@example.com"))
        users, next_cursor = await service.search_users()
        assert len(users) == 2
        assert next_cursor is None

    async def test_search_pagination_with_limit(self, service: UserService) -> None:
        for i in range(5):
            await service.create(UserCreate(email=f"u{i}@example.com"))
        users, next_cursor = await service.search_users(limit=2)
        assert len(users) == 2
        assert next_cursor is not None

        users2, next_cursor2 = await service.search_users(cursor=next_cursor, limit=2)
        assert len(users2) == 2
        assert next_cursor2 is not None

        users3, next_cursor3 = await service.search_users(cursor=next_cursor2, limit=2)
        assert len(users3) == 1
        assert next_cursor3 is None

    async def test_search_sorted_by_id(self, service: UserService) -> None:
        a = await service.create(UserCreate(email="a@example.com"))
        b = await service.create(UserCreate(email="b@example.com"))
        users, _ = await service.search_users()
        # List is ordered by id ascending; with random UUIDs the order is
        # deterministic but not insertion order.
        ids = [u.id for u in users]
        assert set(ids) == {a.id, b.id}
        assert ids == sorted(ids)


class TestListUsersFilters:
    async def test_email_contains_case_insensitive(self, service: UserService) -> None:
        await service.create(UserCreate(email="Alice@Example.com"))
        await service.create(UserCreate(email="bob@example.com"))
        await service.create(UserCreate(email="charlie@other.org"))
        users, _ = await service.search_users(
            search_filter=UserSearchFilter(email__contains="EXAMPLE")
        )
        emails = {u.email for u in users}
        assert emails == {"Alice@example.com", "bob@example.com"}

    async def test_email_contains_partial_substring(self, service: UserService) -> None:
        await service.create(UserCreate(email="alice@example.com"))
        await service.create(UserCreate(email="bob@example.com"))
        await service.create(UserCreate(email="charlie@other.org"))
        users, _ = await service.search_users(
            search_filter=UserSearchFilter(email__contains="alic")
        )
        assert len(users) == 1
        assert users[0].email == "alice@example.com"

    async def test_email_contains_no_match(self, service: UserService) -> None:
        await service.create(UserCreate(email="alice@example.com"))
        users, _ = await service.search_users(
            search_filter=UserSearchFilter(email__contains="nonexistent")
        )
        assert users == []

    async def test_email_eq_exact_match(self, service: UserService) -> None:
        await service.create(UserCreate(email="alice@example.com"))
        await service.create(UserCreate(email="bob@example.com"))
        users, _ = await service.search_users(
            search_filter=UserSearchFilter(email__eq="alice@example.com")
        )
        assert len(users) == 1
        assert users[0].email == "alice@example.com"

    async def test_created_at_gte(self, service: UserService) -> None:
        old = await service.create(UserCreate(email="old@example.com"))
        # Use the DB-side created_at as cutoff to avoid clock/precision skew
        # between Python datetime.now() and PostgreSQL func.now().
        cutoff = old.created_at
        new = await service.create(UserCreate(email="new@example.com"))
        users, _ = await service.search_users(
            search_filter=UserSearchFilter(created_at__gte=cutoff)
        )
        ids = {u.id for u in users}
        assert new.id in ids
        assert old.id in ids

    async def test_created_at_lt(self, service: UserService) -> None:
        old = await service.create(UserCreate(email="old@example.com"))
        cutoff = old.created_at
        await service.create(UserCreate(email="new@example.com"))
        users, _ = await service.search_users(search_filter=UserSearchFilter(created_at__lt=cutoff))
        ids = {u.id for u in users}
        assert old.id not in ids
        assert all(u.email != "new@example.com" for u in users)

    async def test_combined_filters(self, service: UserService) -> None:
        # PostgreSQL func.now() returns transaction-start time, so all creates
        # in the same transaction share a timestamp. Use created_at_lt with a
        # future date to include all users, verifying the email filter narrows.
        await service.create(UserCreate(email="alice@example.com"))
        await service.create(UserCreate(email="bob@example.com"))
        await service.create(UserCreate(email="alice@other.org"))
        users, _ = await service.search_users(
            search_filter=UserSearchFilter(
                email__contains="alice",
                created_at__lt=datetime.now() + timedelta(days=1),
            )
        )
        emails = {u.email for u in users}
        assert emails == {"alice@example.com", "alice@other.org"}

    async def test_filters_with_pagination(self, service: UserService) -> None:
        for i in range(5):
            await service.create(UserCreate(email=f"user{i}@example.com"))
        users, next_cursor = await service.search_users(
            search_filter=UserSearchFilter(email__contains="example"),
            limit=2,
        )
        assert len(users) == 2
        assert next_cursor is not None
        users2, next_cursor2 = await service.search_users(
            search_filter=UserSearchFilter(email__contains="example"),
            cursor=next_cursor,
            limit=2,
        )
        assert len(users2) == 2
        assert next_cursor2 is not None


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
