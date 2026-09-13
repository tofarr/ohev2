"""Unit tests for the governed :class:`SecretProvider` service."""

from __future__ import annotations

import uuid

import pytest
from pydantic import SecretStr, ValidationError
from sqlalchemy.ext.asyncio import AsyncSession
from tests.unit._auth_helpers import make_principal

from openhands.ev2.secret.secret_models import SecretProvider
from openhands.ev2.secret.secret_provider_service import (
    BatchPermissionDeniedError,
    SecretProviderNotFoundError,
    SecretProviderPermissionScopeError,
    SecretProviderService,
)
from openhands.ev2.secret.secret_schemas import (
    SecretProviderCreate,
    SecretProviderSearchFilter,
    SecretProviderUpdate,
)
from openhands.ev2.security.security_models import Action, Permitted
from openhands.ev2.util.search_filter import AllSearchFilter, AttributeFilter, NoneSearchFilter


async def _seed_user(
    session: AsyncSession,
    *,
    email: str = "secrets@example.com",
    username: str = "secrets",
) -> uuid.UUID:
    user = await make_principal(session, email=email, username=username)
    await session.flush()
    return user.id


@pytest.fixture
def service(session: AsyncSession) -> SecretProviderService:
    return SecretProviderService(session, AllSearchFilter[SecretProvider]())


def _payload(**overrides: object) -> SecretProviderCreate:
    data: dict[str, object] = {
        "kind": "static",
        "data": {"token": "plaintext-token", "region": "us-east-1"},
    }
    data.update(overrides)
    return SecretProviderCreate.model_validate(data)


class TestSecretProviderService:
    async def test_create_encrypts_data_at_rest(self, service: SecretProviderService) -> None:
        user_id = await _seed_user(service._session)
        provider = await service.create(_payload(), creator_id=user_id)

        # The ORM row must store JWE ciphertext, never the plaintext.
        assert "plaintext-token" not in provider.data["token"]
        assert provider.kind == "static"
        read = service.to_read(provider)
        serialized = read.model_dump(mode="json")
        assert serialized["data"] == {"token": "**********", "region": "**********"}

    async def test_create_out_of_scope_denied(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        denied = SecretProviderService(session, NoneSearchFilter[SecretProvider]())
        with pytest.raises(SecretProviderPermissionScopeError):
            await denied.create(_payload(), creator_id=user_id)

    async def test_rejects_unknown_kind(self) -> None:
        with pytest.raises(ValidationError):
            SecretProviderCreate(kind="aws_sm", data={})

    async def test_rejects_non_object_data(self) -> None:
        with pytest.raises(ValidationError):
            SecretProviderCreate(kind="static", data="not-an-object")  # type: ignore[arg-type]

    def test_update_allows_no_data(self) -> None:
        # ``data=None`` in an update payload clears no field and is valid.
        assert SecretProviderUpdate(data=None).data is None

    async def test_get_and_get_many_scoped(self, service: SecretProviderService) -> None:
        user_id = await _seed_user(service._session)
        a = await service.create(_payload(), creator_id=user_id)
        b = await service.create(_payload(data={"k": "v"}), creator_id=user_id)

        got = await service.get(a.id)
        assert got.id == a.id

        rows = await service.get_many([a.id, b.id, uuid.uuid4()])
        assert [r.id if r else None for r in rows] == [a.id, b.id, None]
        assert await service.get_many([]) == []

    async def test_get_missing_raises(self, service: SecretProviderService) -> None:
        with pytest.raises(SecretProviderNotFoundError):
            await service.get(uuid.uuid4())

    async def test_search_pagination_and_filter(self, service: SecretProviderService) -> None:
        user_id = await _seed_user(service._session)
        created = [await service.create(_payload(), creator_id=user_id) for _ in range(3)]
        ids = {c.id for c in created}

        page, next_cursor = await service.search(limit=2)
        assert len(page) == 2
        assert next_cursor is not None

        page2, next_cursor2 = await service.search(cursor=next_cursor, limit=2)
        assert len(page2) == 1
        assert next_cursor2 is None

        assert {r.id for r in page + page2} == ids
        assert len({r.id for r in page} & {r.id for r in page2}) == 0

        filtered = await service.search(
            limit=10,
            search_filter=SecretProviderSearchFilter(creator_id__eq=user_id),
        )
        assert {r.id for r in filtered[0]} == ids

    async def test_count(self, service: SecretProviderService) -> None:
        user_id = await _seed_user(service._session)
        await service.create(_payload(), creator_id=user_id)
        await service.create(_payload(data={"k2": "v2"}), creator_id=user_id)
        assert await service.count() == 2
        assert (await service.count(SecretProviderSearchFilter(creator_id__eq=uuid.uuid4()))) == 0

    async def test_update_replaces_data(self, service: SecretProviderService) -> None:
        user_id = await _seed_user(service._session)
        provider = await service.create(_payload(data={"k": "old"}), creator_id=user_id)

        updated = await service.update(provider.id, SecretProviderUpdate(data={"k2": "new"}))
        assert "old" not in updated.data["k2"]
        read = service.to_read(updated)
        assert read.model_dump(mode="json")["data"] == {"k2": "**********"}

    async def test_update_to_denied_provider_raises(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        admin = SecretProviderService(session, AllSearchFilter[SecretProvider]())
        provider = await admin.create(_payload(), creator_id=user_id)
        denied = SecretProviderService(session, NoneSearchFilter[SecretProvider]())
        with pytest.raises(SecretProviderNotFoundError):
            await denied.update(provider.id, SecretProviderUpdate(data={"k": "v"}))

    async def test_delete(self, service: SecretProviderService) -> None:
        user_id = await _seed_user(service._session)
        provider = await service.create(_payload(), creator_id=user_id)
        await service.delete(provider.id)
        with pytest.raises(SecretProviderNotFoundError):
            await service.get(provider.id)

    async def test_batch_create(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        service = SecretProviderService(session, AllSearchFilter[SecretProvider]())
        filters = {
            Action.CREATE: AllSearchFilter[SecretProvider](),
            Action.UPDATE: AllSearchFilter[SecretProvider](),
            Action.DELETE: AllSearchFilter[SecretProvider](),
        }
        from openhands.ev2.secret.secret_schemas import SecretProviderBatchCreate

        results = await service.apply_batch(
            [SecretProviderBatchCreate(data=_payload())],
            filters,
            creator_id=user_id,
        )
        assert results[0] is not None
        assert results[0].kind == "static"

    async def test_batch_update_missing_raises(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        service = SecretProviderService(session, AllSearchFilter[SecretProvider]())
        filters = {
            Action.CREATE: AllSearchFilter[SecretProvider](),
            Action.UPDATE: AllSearchFilter[SecretProvider](),
            Action.DELETE: AllSearchFilter[SecretProvider](),
        }
        from openhands.ev2.secret.secret_schemas import SecretProviderBatchUpdate

        with pytest.raises(SecretProviderNotFoundError):
            await service.apply_batch(
                [
                    SecretProviderBatchUpdate(
                        id=uuid.uuid4(), data=SecretProviderUpdate(data={"x": "y"})
                    )
                ],
                filters,
                creator_id=user_id,
            )

    async def test_batch_delete_missing_raises(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        service = SecretProviderService(session, AllSearchFilter[SecretProvider]())
        filters = {
            Action.CREATE: AllSearchFilter[SecretProvider](),
            Action.UPDATE: AllSearchFilter[SecretProvider](),
            Action.DELETE: AllSearchFilter[SecretProvider](),
        }
        from openhands.ev2.secret.secret_schemas import SecretProviderBatchDelete

        with pytest.raises(SecretProviderNotFoundError):
            await service.apply_batch(
                [SecretProviderBatchDelete(id=uuid.uuid4())],
                filters,
                creator_id=user_id,
            )

    async def test_batch_update_delete_denied_without_filters(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        service = SecretProviderService(session, AllSearchFilter[SecretProvider]())
        from openhands.ev2.secret.secret_schemas import (
            SecretProviderBatchDelete,
            SecretProviderBatchUpdate,
        )

        with pytest.raises(BatchPermissionDeniedError):
            await service.apply_batch(
                [
                    SecretProviderBatchUpdate(
                        id=uuid.uuid4(), data=SecretProviderUpdate(data={"x": "y"})
                    )
                ],
                {Action.UPDATE: None},
                creator_id=user_id,
            )
        with pytest.raises(BatchPermissionDeniedError):
            await service.apply_batch(
                [SecretProviderBatchDelete(id=uuid.uuid4())],
                {Action.DELETE: None},
                creator_id=user_id,
            )

    async def test_delete_out_of_scope_fails_closed(self, session: AsyncSession) -> None:
        owner = await _seed_user(session, email="owner@example.com", username="owner")
        service = SecretProviderService(session, AllSearchFilter[SecretProvider]())
        provider = await service.create(_payload(), creator_id=owner)

        other = await _seed_user(session, email="other@example.com", username="other")
        scoped = SecretProviderService(
            session,
            AttributeFilter[SecretProvider](
                attribute="creator_id",
                condition="eq",
                value=other,
            ),
        )
        # A filter that matches no rows surfaces as 404 (existence not leaked).
        with pytest.raises(SecretProviderNotFoundError):
            await scoped.delete(provider.id)
        # The provider row is untouched by the denied delete.
        assert (await service.get(provider.id)).id == provider.id

    async def test_batch_denied_when_no_action_filter(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        service = SecretProviderService(session, AllSearchFilter[SecretProvider]())
        from openhands.ev2.secret.secret_schemas import SecretProviderBatchCreate

        with pytest.raises(BatchPermissionDeniedError):
            await service.apply_batch(
                [SecretProviderBatchCreate(data=_payload())],
                {Action.CREATE: None},
                creator_id=user_id,
            )

    async def test_permitted_role_grants_scope(self, service: SecretProviderService) -> None:
        user_id = await _seed_user(service._session)
        perm = Permitted()
        filt = perm.to_search_filter(user_id, Action.CREATE)
        scoped = SecretProviderService(service._session, filt)
        provider = await scoped.create(_payload(), creator_id=user_id)
        assert provider.id is not None

    def test_load_secret_str_entry(self) -> None:
        from openhands.ev2.secret.secret_schemas import load_secret_str_entry

        assert load_secret_str_entry(SecretStr("v")).get_secret_value() == "v"
        plain = load_secret_str_entry("plain")
        assert isinstance(plain, SecretStr)
        assert plain.get_secret_value() == "plain"
