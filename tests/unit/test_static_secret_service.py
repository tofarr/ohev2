"""Unit tests for the :class:`StaticSecretService` (static provider store)."""

from __future__ import annotations

import uuid
from datetime import UTC

import pytest
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession
from tests.unit._auth_helpers import make_principal

from openhands.ev2.secret.secret_models import StaticSecret
from openhands.ev2.secret.secret_schemas import (
    StaticSecretCreate,
    StaticSecretSearchFilter,
    StaticSecretUpdate,
)
from openhands.ev2.secret.static_secret_service import (
    BatchPermissionDeniedError,
    StaticSecretNameConflictError,
    StaticSecretNotFoundError,
    StaticSecretPermissionScopeError,
    StaticSecretService,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import AllSearchFilter, NoneSearchFilter


async def _seed_user(
    session: AsyncSession,
    *,
    email: str = "static@example.com",
    username: str = "static",
) -> uuid.UUID:
    user = await make_principal(session, email=email, username=username)
    await session.flush()
    return user.id


@pytest.fixture
def service(session: AsyncSession) -> StaticSecretService:
    return StaticSecretService(session, AllSearchFilter[StaticSecret]())


def _payload(**overrides: object) -> StaticSecretCreate:
    data: dict[str, object] = {
        "name": "API_KEY",
        "value": "hunter2",
    }
    data.update(overrides)
    return StaticSecretCreate.model_validate(data)


class TestStaticSecretService:
    async def test_create_encrypts_value_at_rest(self, service: StaticSecretService) -> None:
        user_id = await _seed_user(service._session)
        secret = await service.create(_payload(), creator_id=user_id)

        assert "hunter2" not in secret.value
        read = service.to_read(secret)
        assert read.name == "API_KEY"
        # The read model never exposes the value.
        assert not hasattr(read, "value")

    async def test_invalid_name_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _payload(name="lower-case-name")
        with pytest.raises(ValidationError):
            _payload(name="1leading-digit")

    async def test_create_out_of_scope_denied(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        denied = StaticSecretService(session, NoneSearchFilter[StaticSecret]())
        with pytest.raises(StaticSecretPermissionScopeError):
            await denied.create(_payload(), creator_id=user_id)

    async def test_duplicate_name_conflict(self, service: StaticSecretService) -> None:
        user_id = await _seed_user(service._session)
        await service.create(_payload(), creator_id=user_id)
        with pytest.raises(StaticSecretNameConflictError):
            await service.create(_payload(name="API_KEY"), creator_id=user_id)

    async def test_get_and_get_many(self, service: StaticSecretService) -> None:
        user_id = await _seed_user(service._session)
        a = await service.create(_payload(name="KEY_A"), creator_id=user_id)
        b = await service.create(_payload(name="KEY_B"), creator_id=user_id)

        got = await service.get(a.id)
        assert got.id == a.id

        rows = await service.get_many([a.id, b.id, uuid.uuid4()])
        assert [r.id if r else None for r in rows] == [a.id, b.id, None]
        assert await service.get_many([]) == []

    async def test_get_missing_raises(self, service: StaticSecretService) -> None:
        with pytest.raises(StaticSecretNotFoundError):
            await service.get(uuid.uuid4())

    async def test_search_pagination_and_filter(self, service: StaticSecretService) -> None:
        user_id = await _seed_user(service._session)
        created = [
            await service.create(_payload(name=f"KEY_{i}"), creator_id=user_id) for i in range(3)
        ]
        ids = {c.id for c in created}

        page, next_cursor = await service.search(limit=2)
        assert len(page) == 2
        assert next_cursor is not None

        more, next_cursor2 = await service.search(cursor=next_cursor, limit=2)
        assert len(more) == 1
        assert next_cursor2 is None

        assert {r.id for r in page + more} == ids
        assert len({r.id for r in page} & {r.id for r in more}) == 0

        filtered, _ = await service.search(
            limit=10,
            search_filter=StaticSecretSearchFilter(name__contains="KEY"),
        )
        assert {r.id for r in filtered} == ids

    async def test_count(self, service: StaticSecretService) -> None:
        user_id = await _seed_user(service._session)
        await service.create(_payload(name="KEY_1"), creator_id=user_id)
        await service.create(_payload(name="KEY_2"), creator_id=user_id)
        assert await service.count() == 2

    async def test_update_changes_name_value_and_validity(
        self,
        service: StaticSecretService,
    ) -> None:
        from datetime import datetime

        user_id = await _seed_user(service._session)
        secret = await service.create(_payload(name="OLD_KEY"), creator_id=user_id)
        when = datetime(2030, 1, 1, tzinfo=UTC)

        updated = await service.update(
            secret.id,
            StaticSecretUpdate(name="NEW_KEY", value="new-value", expires_at=when),
        )
        assert updated.name == "NEW_KEY"
        assert "new-value" not in updated.value
        assert updated.expires_at == when

    async def test_update_name_conflict(self, service: StaticSecretService) -> None:
        user_id = await _seed_user(service._session)
        a = await service.create(_payload(name="KEY_A"), creator_id=user_id)
        await service.create(_payload(name="KEY_B"), creator_id=user_id)
        with pytest.raises(StaticSecretNameConflictError):
            await service.update(a.id, StaticSecretUpdate(name="KEY_B"))

    async def test_update_missing_raises(self, service: StaticSecretService) -> None:
        with pytest.raises(StaticSecretNotFoundError):
            await service.update(uuid.uuid4(), StaticSecretUpdate(name="KEY_X"))

    async def test_update_with_only_value(self, service: StaticSecretService) -> None:
        user_id = await _seed_user(service._session)
        secret = await service.create(_payload(name="KEY_V"), creator_id=user_id)
        updated = await service.update(secret.id, StaticSecretUpdate(value="rotated"))
        assert updated.name == "KEY_V"
        assert "rotated" not in updated.value

    async def test_update_valid_at(self, service: StaticSecretService) -> None:
        from datetime import datetime

        user_id = await _seed_user(service._session)
        secret = await service.create(_payload(name="KEY_VA"), creator_id=user_id)
        when = datetime(2029, 5, 1, tzinfo=UTC)
        updated = await service.update(secret.id, StaticSecretUpdate(valid_at=when))
        assert updated.valid_at == when
        assert updated.expires_at is None

    async def test_delete(self, service: StaticSecretService) -> None:
        user_id = await _seed_user(service._session)
        secret = await service.create(_payload(), creator_id=user_id)
        await service.delete(secret.id)
        with pytest.raises(StaticSecretNotFoundError):
            await service.get(secret.id)

    async def test_batch_create(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        service = StaticSecretService(session, AllSearchFilter[StaticSecret]())
        from openhands.ev2.secret.secret_schemas import StaticSecretBatchCreate

        results = await service.apply_batch(
            [StaticSecretBatchCreate(data=_payload(name="BATCH_KEY"))],
            {Action.CREATE: AllSearchFilter[StaticSecret]()},
            creator_id=user_id,
        )
        assert results[0] is not None
        assert results[0].name == "BATCH_KEY"

    async def test_batch_denied_without_create_filter(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        service = StaticSecretService(session, AllSearchFilter[StaticSecret]())
        from openhands.ev2.secret.secret_schemas import StaticSecretBatchCreate

        with pytest.raises(BatchPermissionDeniedError):
            await service.apply_batch(
                [StaticSecretBatchCreate(data=_payload())],
                {Action.CREATE: None},
                creator_id=user_id,
            )

    async def test_batch_update_delete_denied_without_filters(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        secret = await StaticSecretService(session, AllSearchFilter[StaticSecret]()).create(
            _payload(name="FIELD_KEY"), creator_id=user_id
        )
        service = StaticSecretService(session, AllSearchFilter[StaticSecret]())
        from openhands.ev2.secret.secret_schemas import (
            StaticSecretBatchDelete,
            StaticSecretBatchUpdate,
        )

        with pytest.raises(BatchPermissionDeniedError):
            await service.apply_batch(
                [StaticSecretBatchUpdate(id=secret.id, data=StaticSecretUpdate(value="x"))],
                {Action.UPDATE: None},
                creator_id=user_id,
            )
        with pytest.raises(BatchPermissionDeniedError):
            await service.apply_batch(
                [StaticSecretBatchDelete(id=secret.id)],
                {Action.DELETE: None},
                creator_id=user_id,
            )
