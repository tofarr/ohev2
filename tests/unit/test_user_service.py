"""Unit tests for the user service (DB-backed)."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.user.user_models import User
from openhands.ev2.user.user_schemas import UserCreate, UserSearchFilter, UserUpdate
from openhands.ev2.user.user_service import (
    UserEmailConflictError,
    UserNotFoundError,
    UserService,
    UserUsernameConflictError,
)
from openhands.ev2.util.search_filter import AllSearchFilter

# Unrestricted permission filter for service-level tests that exercise the
# CRUD mechanics rather than permission scoping (covered in route tests).
_ALL = AllSearchFilter[User]()


@pytest.fixture
def service(session: AsyncSession) -> UserService:
    return UserService(session, _ALL)


class TestCreateUser:
    async def test_create_user(self, service: UserService) -> None:
        user = await service.create(UserCreate(email="alice@example.com", username="alice"))
        assert user.id is not None
        assert isinstance(user.id, uuid.UUID)
        assert user.email == "alice@example.com"
        assert user.created_at is not None
        assert user.updated_at is not None

    async def test_create_duplicate_email_conflicts(self, service: UserService) -> None:
        await service.create(UserCreate(email="alice@example.com", username="alice"))
        with pytest.raises(UserEmailConflictError):
            await service.create(UserCreate(email="alice@example.com", username="alice2"))

    async def test_create_invalid_email_rejected_at_schema(self) -> None:
        with pytest.raises(ValueError):
            UserCreate(email="not-an-email", username="not-an-email")

    async def test_create_defaults_to_unrestricted_scope(self, session: AsyncSession) -> None:
        # No perm_filter supplied to the service: defaults to AllSearchFilter
        # (unrestricted scope).
        service = UserService(session)
        user = await service.create(UserCreate(email="default@example.com", username="default"))
        assert user.email == "default@example.com"


class TestGetUser:
    async def test_get_existing_user(self, service: UserService) -> None:
        created = await service.create(UserCreate(email="bob@example.com", username="bob"))
        fetched = await service.get(created.id)
        assert fetched.id == created.id
        assert fetched.email == "bob@example.com"

    async def test_get_missing_user_raises(self, service: UserService) -> None:
        with pytest.raises(UserNotFoundError):
            await service.get(uuid.uuid4())


class TestGetManyUsers:
    async def test_get_many_aligned_with_nulls(self, service: UserService) -> None:
        a = await service.create(UserCreate(email="a@example.com", username="a"))
        b = await service.create(UserCreate(email="b@example.com", username="b"))
        missing = uuid.uuid4()
        result = await service.get_many([a.id, missing, b.id])
        assert len(result) == 3
        assert result[0] is not None and result[0].id == a.id
        assert result[1] is None
        assert result[2] is not None and result[2].id == b.id

    async def test_get_many_empty_list_no_db_hit(self, service: UserService) -> None:
        assert await service.get_many([]) == []

    async def test_get_many_preserves_duplicates(self, service: UserService) -> None:
        a = await service.create(UserCreate(email="dup@example.com", username="dup"))
        result = await service.get_many([a.id, a.id])
        assert len(result) == 2
        assert result[0] is not None and result[0].id == a.id
        assert result[1] is not None and result[1].id == a.id

    async def test_get_many_all_missing(self, service: UserService) -> None:
        result = await service.get_many([uuid.uuid4(), uuid.uuid4()])
        assert result == [None, None]

    async def test_get_many_respects_perm_filter(self, session: AsyncSession) -> None:
        from openhands.ev2.util.search_filter import NoneSearchFilter

        a = await UserService(session, _ALL).create(
            UserCreate(email="scoped@example.com", username="scoped")
        )
        denied = UserService(session, NoneSearchFilter[User]())
        result = await denied.get_many([a.id])
        assert result == [None]


class TestListUsers:
    async def test_search_empty(self, service: UserService) -> None:
        users, next_cursor = await service.search_users()
        assert users == []
        assert next_cursor is None

    async def test_search_returns_users(self, service: UserService) -> None:
        await service.create(UserCreate(email="a@example.com", username="a"))
        await service.create(UserCreate(email="b@example.com", username="b"))
        users, next_cursor = await service.search_users()
        assert len(users) == 2
        assert next_cursor is None

    async def test_search_pagination_with_limit(self, service: UserService) -> None:
        for i in range(5):
            await service.create(UserCreate(email=f"u{i}@example.com", username=f"u{i}"))
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
        a = await service.create(UserCreate(email="a@example.com", username="a"))
        b = await service.create(UserCreate(email="b@example.com", username="b"))
        users, _ = await service.search_users()
        # List is ordered by id ascending; with random UUIDs the order is
        # deterministic but not insertion order.
        ids = [u.id for u in users]
        assert set(ids) == {a.id, b.id}
        assert ids == sorted(ids)


class TestListUsersFilters:
    async def test_email_contains_case_insensitive(self, service: UserService) -> None:
        await service.create(UserCreate(email="Alice@Example.com", username="alice"))
        await service.create(UserCreate(email="bob@example.com", username="bob"))
        await service.create(UserCreate(email="charlie@other.org", username="charlie"))
        users, _ = await service.search_users(
            search_filter=UserSearchFilter(email__contains="EXAMPLE")
        )
        emails = {u.email for u in users}
        assert emails == {"Alice@example.com", "bob@example.com"}

    async def test_email_contains_partial_substring(self, service: UserService) -> None:
        await service.create(UserCreate(email="alice@example.com", username="alice"))
        await service.create(UserCreate(email="bob@example.com", username="bob"))
        await service.create(UserCreate(email="charlie@other.org", username="charlie"))
        users, _ = await service.search_users(
            search_filter=UserSearchFilter(email__contains="alic")
        )
        assert len(users) == 1
        assert users[0].email == "alice@example.com"

    async def test_email_contains_no_match(self, service: UserService) -> None:
        await service.create(UserCreate(email="alice@example.com", username="alice"))
        users, _ = await service.search_users(
            search_filter=UserSearchFilter(email__contains="nonexistent")
        )
        assert users == []

    async def test_email_eq_exact_match(self, service: UserService) -> None:
        await service.create(UserCreate(email="alice@example.com", username="alice"))
        await service.create(UserCreate(email="bob@example.com", username="bob"))
        users, _ = await service.search_users(
            search_filter=UserSearchFilter(email__eq="alice@example.com")
        )
        assert len(users) == 1
        assert users[0].email == "alice@example.com"

    async def test_created_at_gte(self, service: UserService) -> None:
        old = await service.create(UserCreate(email="old@example.com", username="old"))
        # Use the DB-side created_at as cutoff to avoid clock/precision skew
        # between Python datetime.now() and PostgreSQL func.now().
        cutoff = old.created_at
        new = await service.create(UserCreate(email="new@example.com", username="new"))
        users, _ = await service.search_users(
            search_filter=UserSearchFilter(created_at__gte=cutoff)
        )
        ids = {u.id for u in users}
        assert new.id in ids
        assert old.id in ids

    async def test_created_at_lt(self, service: UserService) -> None:
        old = await service.create(UserCreate(email="old@example.com", username="old"))
        cutoff = old.created_at
        await service.create(UserCreate(email="new@example.com", username="new"))
        users, _ = await service.search_users(search_filter=UserSearchFilter(created_at__lt=cutoff))
        ids = {u.id for u in users}
        assert old.id not in ids
        assert all(u.email != "new@example.com" for u in users)

    async def test_combined_filters(self, service: UserService) -> None:
        # PostgreSQL func.now() returns transaction-start time, so all creates
        # in the same transaction share a timestamp. Use created_at_lt with a
        # future date to include all users, verifying the email filter narrows.
        await service.create(UserCreate(email="alice@example.com", username="alice"))
        await service.create(UserCreate(email="bob@example.com", username="bob"))
        await service.create(UserCreate(email="alice@other.org", username="alice2"))
        users, _ = await service.search_users(
            search_filter=UserSearchFilter(
                email__contains="alice",
                created_at__lt=datetime.now() + timedelta(days=1),
            ),
        )
        emails = {u.email for u in users}
        assert emails == {"alice@example.com", "alice@other.org"}

    async def test_filters_with_pagination(self, service: UserService) -> None:
        for i in range(5):
            await service.create(UserCreate(email=f"user{i}@example.com", username=f"user{i}"))
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
        user = await service.create(UserCreate(email="old@example.com", username="old"))
        updated = await service.update(user.id, UserUpdate(email="new@example.com"))
        assert updated.email == "new@example.com"

    async def test_update_no_fields_keeps_email(self, service: UserService) -> None:
        user = await service.create(UserCreate(email="keep@example.com", username="keep"))
        updated = await service.update(user.id, UserUpdate())
        assert updated.email == "keep@example.com"

    async def test_update_missing_user_raises(self, service: UserService) -> None:
        with pytest.raises(UserNotFoundError):
            await service.update(uuid.uuid4(), UserUpdate(email="x@example.com"))

    async def test_update_to_existing_email_conflicts(self, service: UserService) -> None:
        await service.create(UserCreate(email="taken@example.com", username="taken"))
        user = await service.create(UserCreate(email="other@example.com", username="other"))
        with pytest.raises(UserEmailConflictError):
            await service.update(user.id, UserUpdate(email="taken@example.com"))

    async def test_update_defaults_to_unrestricted_scope(self, session: AsyncSession) -> None:
        service = UserService(session)
        user = await service.create(UserCreate(email="orig@example.com", username="orig"))
        # No perm_filter supplied to the service: defaults to AllSearchFilter
        # (unrestricted scope).
        updated = await service.update(user.id, UserUpdate(email="replaced@example.com"))
        assert updated.email == "replaced@example.com"


class TestDeleteUser:
    async def test_delete_user(self, service: UserService) -> None:
        user = await service.create(UserCreate(email="del@example.com", username="del"))
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
        await service.create(UserCreate(email="a@example.com", username="a"))
        await service.create(UserCreate(email="b@example.com", username="b"))
        assert await service.count() == 2


class TestNewFields:
    async def test_create_defaults_enabled_true(self, service: UserService) -> None:
        user = await service.create(UserCreate(email="alice@example.com", username="alice"))
        assert user.enabled is True

    async def test_create_explicit_enabled_false(self, service: UserService) -> None:
        user = await service.create(
            UserCreate(email="alice@example.com", username="alice", enabled=False)
        )
        assert user.enabled is False

    async def test_create_stores_username(self, service: UserService) -> None:
        user = await service.create(UserCreate(email="alice@example.com", username="alice"))
        assert user.username == "alice"

    async def test_create_strips_username_whitespace(self) -> None:
        user = UserCreate(email="alice@example.com", username="  alice  ")
        assert user.username == "alice"

    async def test_create_rejects_empty_username(self) -> None:
        with pytest.raises(ValueError):
            UserCreate(email="alice@example.com", username="")

    async def test_create_rejects_whitespace_only_username(self) -> None:
        with pytest.raises(ValueError):
            UserCreate(email="alice@example.com", username="   ")

    async def test_update_username_none_passes_through(self) -> None:
        update = UserUpdate()
        assert update.username is None

    async def test_create_duplicate_username_conflicts(self, service: UserService) -> None:
        await service.create(UserCreate(email="alice@example.com", username="alice"))
        with pytest.raises(UserUsernameConflictError):
            await service.create(UserCreate(email="bob@example.com", username="alice"))

    async def test_update_username(self, service: UserService) -> None:
        user = await service.create(UserCreate(email="alice@example.com", username="alice"))
        updated = await service.update(user.id, UserUpdate(username="alice2"))
        assert updated.username == "alice2"

    async def test_update_to_existing_username_conflicts(self, service: UserService) -> None:
        await service.create(UserCreate(email="a@example.com", username="taken"))
        user = await service.create(UserCreate(email="b@example.com", username="other"))
        with pytest.raises(UserUsernameConflictError):
            await service.update(user.id, UserUpdate(username="taken"))

    async def test_update_enabled(self, service: UserService) -> None:
        user = await service.create(UserCreate(email="alice@example.com", username="alice"))
        assert user.enabled is True
        updated = await service.update(user.id, UserUpdate(enabled=False))
        assert updated.enabled is False

    async def test_search_username_contains(self, service: UserService) -> None:
        await service.create(UserCreate(email="a@example.com", username="alice"))
        await service.create(UserCreate(email="b@example.com", username="bob"))
        users, _ = await service.search_users(
            search_filter=UserSearchFilter(username__contains="ALI")
        )
        assert len(users) == 1
        assert users[0].username == "alice"

    async def test_search_username_eq(self, service: UserService) -> None:
        await service.create(UserCreate(email="a@example.com", username="alice"))
        await service.create(UserCreate(email="b@example.com", username="bob"))
        users, _ = await service.search_users(search_filter=UserSearchFilter(username__eq="bob"))
        assert len(users) == 1
        assert users[0].username == "bob"

    async def test_search_enabled_eq(self, service: UserService) -> None:
        await service.create(UserCreate(email="a@example.com", username="a", enabled=True))
        await service.create(UserCreate(email="b@example.com", username="b", enabled=False))
        users, _ = await service.search_users(search_filter=UserSearchFilter(enabled__eq=False))
        assert len(users) == 1
        assert users[0].username == "b"


class TestPasswordHashing:
    """Password is stored as a bcrypt salted hash; never plaintext or reversible."""

    async def test_create_without_password_stores_none(self, service: UserService) -> None:
        user = await service.create(UserCreate(email="alice@example.com", username="alice"))
        assert user.password is None

    async def test_create_with_password_hashes_at_rest(self, service: UserService) -> None:
        plaintext = "hunter2"
        user = await service.create(
            UserCreate(email="alice@example.com", username="alice", password=plaintext)
        )
        # Stored value is a bcrypt hash, never the plaintext.
        assert user.password is not None
        assert user.password != plaintext
        assert user.password.startswith("$2")
        # And verifies against the plaintext.
        assert service.verify_password(plaintext, user) is True

    async def test_update_password_hashes_at_rest(self, service: UserService) -> None:
        user = await service.create(UserCreate(email="alice@example.com", username="alice"))
        assert user.password is None
        updated = await service.update(user.id, UserUpdate(password="newpass"))
        assert updated.password is not None
        assert updated.password != "newpass"
        assert service.verify_password("newpass", updated) is True

    async def test_each_hash_yields_distinct_hash(self, service: UserService) -> None:
        # bcrypt includes a fresh salt per hash, so the same plaintext hashes
        # to a different value each time.
        u1 = await service.create(
            UserCreate(email="a@example.com", username="a", password="secret")
        )
        u2 = await service.create(
            UserCreate(email="b@example.com", username="b", password="secret")
        )
        assert u1.password != u2.password
        assert service.verify_password("secret", u1) is True
        assert service.verify_password("secret", u2) is True

    async def test_verify_password_rejects_wrong_password(self, service: UserService) -> None:
        user = await service.create(
            UserCreate(email="a@example.com", username="a", password="secret")
        )
        assert service.verify_password("wrong", user) is False
        assert service.verify_password("", user) is False

    async def test_verify_password_rejects_when_no_password_set(self, service: UserService) -> None:
        user = await service.create(UserCreate(email="nopass@example.com", username="nopass"))
        assert user.password is None
        assert service.verify_password("anything", user) is False

    async def test_password_never_in_read_schema(self) -> None:
        from openhands.ev2.user.user_schemas import UserRead

        assert "password" not in UserRead.model_fields

    async def test_authenticate_returns_enabled_user(self, service: UserService) -> None:
        await service.create(
            UserCreate(email="a@example.com", username="alice", password="hunter2")
        )
        user = await service.authenticate("alice", "hunter2")
        assert user is not None
        assert user.username == "alice"

    async def test_authenticate_rejects_wrong_password(self, service: UserService) -> None:
        await service.create(
            UserCreate(email="a@example.com", username="alice", password="hunter2")
        )
        assert await service.authenticate("alice", "wrong") is None

    async def test_authenticate_rejects_unknown_user(self, service: UserService) -> None:
        await service.create(
            UserCreate(email="a@example.com", username="alice", password="hunter2")
        )
        assert await service.authenticate("bob", "hunter2") is None

    async def test_authenticate_rejects_disabled_user(self, service: UserService) -> None:
        await service.create(
            UserCreate(email="a@example.com", username="alice", password="hunter2", enabled=False)
        )
        assert await service.authenticate("alice", "hunter2") is None

    async def test_authenticate_rejects_user_without_password(self, service: UserService) -> None:
        await service.create(UserCreate(email="a@example.com", username="alice"))
        assert await service.authenticate("alice", "anything") is None

    async def test_get_by_username(self, service: UserService) -> None:
        await service.create(UserCreate(email="a@example.com", username="alice"))
        found = await service.get_by_username("alice")
        assert found is not None
        assert found.username == "alice"
        assert await service.get_by_username("nobody") is None
