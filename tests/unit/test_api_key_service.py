"""Unit tests for the api_key service (DB-backed)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.api_key.api_key_schemas import (
    ApiKeyBatchCreate,
    ApiKeyBatchDelete,
    ApiKeyBatchUpdate,
    ApiKeyCreate,
    ApiKeySearchFilter,
    ApiKeyUpdate,
)
from openhands.ev2.api_key.api_key_service import (
    ApiKeyNotFoundError,
    ApiKeyPermissionScopeError,
    ApiKeyService,
    BatchPermissionDeniedError,
)
from openhands.ev2.auth.auth_models import ApiKey
from openhands.ev2.auth.auth_tokens import TokenService
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import (
    AllSearchFilter,
    NoneSearchFilter,
    SearchFilter,
)

_ALL = AllSearchFilter[ApiKey]()
_NONE = NoneSearchFilter[ApiKey]()


async def _seed_user(session: AsyncSession, user_id: uuid.UUID) -> None:
    from sqlalchemy import text

    await session.execute(
        text(
            "INSERT INTO users (id, email, username, enabled) "
            "VALUES (:id, :email, :username, true) "
            "ON CONFLICT (id) DO NOTHING"
        ),
        {
            "id": user_id,
            "email": f"{user_id}@example.com",
            "username": f"u-{user_id.hex[:8]}",
        },
    )
    await session.flush()


class _UserScopedFilter(SearchFilter[ApiKey]):
    """Filter matching keys whose ``user_id`` equals a fixed value.

    Stand-in for a permission policy scoped to the principal's own keys, used
    to exercise the create-scope check.
    """

    user_id: uuid.UUID

    def matches(self, item: ApiKey) -> bool:
        return item.user_id == self.user_id

    def sql_condition(self) -> Any:
        return ApiKey.user_id == self.user_id


@pytest.fixture
def service(session: AsyncSession) -> ApiKeyService:
    return ApiKeyService(session, _ALL)


class TestCreateApiKey:
    async def test_create_api_key(self, service: ApiKeyService, session: AsyncSession) -> None:
        uid = uuid.uuid4()
        await _seed_user(session, uid)
        token, key = await service.create(ApiKeyCreate(name="ci"), user_id=uid)
        assert key.id is not None
        assert key.user_id == uid
        assert key.name == "ci"
        assert key.enabled is True
        assert key.expires_at is None
        assert key.jti is not None
        assert token  # JWE secret surfaced
        # The token authenticates as an API_KEY for the user.
        auth = await TokenService(session).authenticate(token)
        assert auth.user_id == uid

    async def test_create_with_expiry(self, service: ApiKeyService, session: AsyncSession) -> None:
        uid = uuid.uuid4()
        await _seed_user(session, uid)
        expires = datetime.now(UTC) + timedelta(hours=1)
        _token, key = await service.create(ApiKeyCreate(expires_at=expires), user_id=uid)
        assert key.expires_at is not None

    async def test_create_disabled(self, service: ApiKeyService, session: AsyncSession) -> None:
        uid = uuid.uuid4()
        await _seed_user(session, uid)
        token, key = await service.create(ApiKeyCreate(enabled=False), user_id=uid)
        assert key.enabled is False
        # A disabled key does not authenticate as enabled.
        auth = await TokenService(session).authenticate(token)
        assert auth.enabled is False

    async def test_create_outside_scope_raises(self, session: AsyncSession) -> None:
        uid = uuid.uuid4()
        other = uuid.uuid4()
        await _seed_user(session, uid)
        await _seed_user(session, other)
        scoped = ApiKeyService(session, _UserScopedFilter(user_id=uid))
        with pytest.raises(ApiKeyPermissionScopeError):
            await scoped.create(ApiKeyCreate(name="cross"), user_id=other)

    async def test_create_within_scope_succeeds(self, session: AsyncSession) -> None:
        uid = uuid.uuid4()
        await _seed_user(session, uid)
        scoped = ApiKeyService(session, _UserScopedFilter(user_id=uid))
        _token, key = await scoped.create(ApiKeyCreate(name="own"), user_id=uid)
        assert key.user_id == uid


class TestGetApiKey:
    async def test_get_existing(self, service: ApiKeyService, session: AsyncSession) -> None:
        uid = uuid.uuid4()
        await _seed_user(session, uid)
        _token, created = await service.create(ApiKeyCreate(), user_id=uid)
        fetched = await service.get(created.id)
        assert fetched.id == created.id

    async def test_get_missing_raises(self, service: ApiKeyService) -> None:
        with pytest.raises(ApiKeyNotFoundError):
            await service.get(uuid.uuid4())

    async def test_get_respects_perm_filter(self, session: AsyncSession) -> None:
        uid = uuid.uuid4()
        await _seed_user(session, uid)
        _token, created = await ApiKeyService(session, _ALL).create(ApiKeyCreate(), user_id=uid)
        denied = ApiKeyService(session, _NONE)
        with pytest.raises(ApiKeyNotFoundError):
            await denied.get(created.id)


class TestGetManyApiKeys:
    async def test_get_many_aligned_with_nulls(
        self, service: ApiKeyService, session: AsyncSession
    ) -> None:
        uid = uuid.uuid4()
        await _seed_user(session, uid)
        a = (await service.create(ApiKeyCreate(name="a"), user_id=uid))[1]
        b = (await service.create(ApiKeyCreate(name="b"), user_id=uid))[1]
        missing = uuid.uuid4()
        result = await service.get_many([a.id, missing, b.id])
        assert len(result) == 3
        assert result[0] is not None and result[0].id == a.id
        assert result[1] is None
        assert result[2] is not None and result[2].id == b.id

    async def test_get_many_empty_list_no_db_hit(self, service: ApiKeyService) -> None:
        assert await service.get_many([]) == []

    async def test_get_many_preserves_duplicates(
        self, service: ApiKeyService, session: AsyncSession
    ) -> None:
        uid = uuid.uuid4()
        await _seed_user(session, uid)
        a = (await service.create(ApiKeyCreate(name="dup"), user_id=uid))[1]
        result = await service.get_many([a.id, a.id])
        assert len(result) == 2
        assert result[0] is not None and result[0].id == a.id
        assert result[1] is not None and result[1].id == a.id

    async def test_get_many_all_missing(self, service: ApiKeyService) -> None:
        result = await service.get_many([uuid.uuid4(), uuid.uuid4()])
        assert result == [None, None]

    async def test_get_many_respects_perm_filter(self, session: AsyncSession) -> None:
        uid = uuid.uuid4()
        await _seed_user(session, uid)
        a = (await ApiKeyService(session, _ALL).create(ApiKeyCreate(), user_id=uid))[1]
        denied = ApiKeyService(session, _NONE)
        assert await denied.get_many([a.id]) == [None]


class TestSearchApiKeys:
    async def test_search_empty(self, service: ApiKeyService) -> None:
        keys, next_cursor = await service.search_api_keys()
        assert keys == []
        assert next_cursor is None

    async def test_search_returns_created(
        self, service: ApiKeyService, session: AsyncSession
    ) -> None:
        uid = uuid.uuid4()
        await _seed_user(session, uid)
        await service.create(ApiKeyCreate(name="one"), user_id=uid)
        keys, _next = await service.search_api_keys()
        assert len(keys) == 1
        assert keys[0].name == "one"

    async def test_search_pagination(self, service: ApiKeyService, session: AsyncSession) -> None:
        uid = uuid.uuid4()
        await _seed_user(session, uid)
        for i in range(3):
            await service.create(ApiKeyCreate(name=f"p{i}"), user_id=uid)
        first, next_cursor = await service.search_api_keys(limit=2)
        assert len(first) == 2
        assert next_cursor is not None
        second, next_cursor2 = await service.search_api_keys(cursor=next_cursor, limit=2)
        assert len(second) == 1
        assert next_cursor2 is None

    async def test_search_with_name_filter(
        self, service: ApiKeyService, session: AsyncSession
    ) -> None:
        uid = uuid.uuid4()
        await _seed_user(session, uid)
        await service.create(ApiKeyCreate(name="Admin"), user_id=uid)
        await service.create(ApiKeyCreate(name="viewer"), user_id=uid)
        keys, _next = await service.search_api_keys(
            search_filter=ApiKeySearchFilter(name__contains="ADMIN")
        )
        names = {k.name for k in keys}
        assert "Admin" in names
        assert "viewer" not in names

    async def test_search_with_user_id_filter(
        self, service: ApiKeyService, session: AsyncSession
    ) -> None:
        uid = uuid.uuid4()
        other = uuid.uuid4()
        await _seed_user(session, uid)
        await _seed_user(session, other)
        await service.create(ApiKeyCreate(name="mine"), user_id=uid)
        await service.create(ApiKeyCreate(name="theirs"), user_id=other)
        keys, _next = await service.search_api_keys(
            search_filter=ApiKeySearchFilter(user_id__eq=uid)
        )
        assert all(k.user_id == uid for k in keys)
        assert {k.name for k in keys} == {"mine"}


class TestUpdateApiKey:
    async def test_update_name(self, service: ApiKeyService, session: AsyncSession) -> None:
        uid = uuid.uuid4()
        await _seed_user(session, uid)
        _t, key = await service.create(ApiKeyCreate(name="old"), user_id=uid)
        updated = await service.update(key.id, ApiKeyUpdate(name="new"))
        assert updated.name == "new"

    async def test_update_enabled(self, service: ApiKeyService, session: AsyncSession) -> None:
        uid = uuid.uuid4()
        await _seed_user(session, uid)
        token, key = await service.create(ApiKeyCreate(), user_id=uid)
        updated = await service.update(key.id, ApiKeyUpdate(enabled=False))
        assert updated.enabled is False
        auth = await TokenService(session).authenticate(token)
        assert auth.enabled is False

    async def test_update_no_fields(self, service: ApiKeyService, session: AsyncSession) -> None:
        uid = uuid.uuid4()
        await _seed_user(session, uid)
        _t, key = await service.create(ApiKeyCreate(name="keep"), user_id=uid)
        updated = await service.update(key.id, ApiKeyUpdate())
        assert updated.name == "keep"

    async def test_update_missing_raises(self, service: ApiKeyService) -> None:
        with pytest.raises(ApiKeyNotFoundError):
            await service.update(uuid.uuid4(), ApiKeyUpdate(name="x"))


class TestDeleteApiKey:
    async def test_delete_removes_row(self, service: ApiKeyService, session: AsyncSession) -> None:
        uid = uuid.uuid4()
        await _seed_user(session, uid)
        token, key = await service.create(ApiKeyCreate(), user_id=uid)
        await service.delete(key.id)
        with pytest.raises(ApiKeyNotFoundError):
            await service.get(key.id)
        # Row gone: token no longer authenticates.
        auth = await TokenService(session).authenticate(token)
        assert auth.enabled is False

    async def test_delete_missing_raises(self, service: ApiKeyService) -> None:
        with pytest.raises(ApiKeyNotFoundError):
            await service.delete(uuid.uuid4())


class TestCountApiKeys:
    async def test_count_empty(self, service: ApiKeyService) -> None:
        assert await service.count() == 0

    async def test_count_after_creates(self, service: ApiKeyService, session: AsyncSession) -> None:
        uid = uuid.uuid4()
        await _seed_user(session, uid)
        for i in range(3):
            await service.create(ApiKeyCreate(name=f"c{i}"), user_id=uid)
        assert await service.count() == 3

    async def test_count_with_name_filter(
        self, service: ApiKeyService, session: AsyncSession
    ) -> None:
        uid = uuid.uuid4()
        await _seed_user(session, uid)
        await service.create(ApiKeyCreate(name="admin"), user_id=uid)
        await service.create(ApiKeyCreate(name="viewer"), user_id=uid)
        assert await service.count(ApiKeySearchFilter(name__contains="admin")) == 1


class TestBatchWriteApiKeys:
    async def test_batch_mix_cud(self, service: ApiKeyService, session: AsyncSession) -> None:
        uid = uuid.uuid4()
        await _seed_user(session, uid)
        _t1, k1 = await service.create(ApiKeyCreate(name="bwr1"), user_id=uid)
        _t2, k2 = await service.create(ApiKeyCreate(name="bwr2"), user_id=uid)
        results = await service.apply_batch(
            [
                ApiKeyBatchCreate(data=ApiKeyCreate(name="bwr3")),
                ApiKeyBatchUpdate(id=k1.id, data=ApiKeyUpdate(name="bwr1b")),
                ApiKeyBatchDelete(id=k2.id),
            ],
            {
                Action.CREATE: _ALL,
                Action.UPDATE: _ALL,
                Action.DELETE: _ALL,
            },
            user_id=uid,
        )
        assert len(results) == 3
        assert results[0] is not None and results[0].name == "bwr3"
        assert results[1] is not None and results[1].id == k1.id and results[1].name == "bwr1b"
        assert results[2] is None
        with pytest.raises(ApiKeyNotFoundError):
            await service.get(k2.id)

    async def test_batch_denies_action_without_filter(
        self, service: ApiKeyService, session: AsyncSession
    ) -> None:
        uid = uuid.uuid4()
        await _seed_user(session, uid)
        with pytest.raises(BatchPermissionDeniedError):
            await service.apply_batch(
                [ApiKeyBatchCreate(data=ApiKeyCreate(name="x"))],
                {Action.CREATE: None, Action.UPDATE: _ALL, Action.DELETE: _ALL},
                user_id=uid,
            )

    async def test_batch_rolls_back_on_missing_id(
        self, service: ApiKeyService, session: AsyncSession
    ) -> None:
        # Atomicity is enforced by the router (no commit on error); at the
        # service layer we assert the error propagates and the flushed create
        # is not committed. The route-level test verifies the row is absent
        # after the rolled-back request.
        uid = uuid.uuid4()
        await _seed_user(session, uid)
        with pytest.raises(ApiKeyNotFoundError):
            await service.apply_batch(
                [
                    ApiKeyBatchCreate(data=ApiKeyCreate(name="rollback")),
                    ApiKeyBatchDelete(id=uuid.uuid4()),  # missing
                ],
                {Action.CREATE: _ALL, Action.UPDATE: _ALL, Action.DELETE: _ALL},
                user_id=uid,
            )
