"""Unit tests for the LLM service layer (DB-backed, transactional session)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from tests.unit._auth_helpers import make_principal

from openhands.ev2.llm.llm_models import StoredLLM, StoredProviderConnection
from openhands.ev2.llm.llm_schemas import (
    LLMCreate,
    LLMUpdate,
    ProviderConnectionCreate,
    ProviderConnectionUpdate,
)
from openhands.ev2.llm.llm_service import (
    LLMConfigError,
    LLMNotFoundError,
    LLMPermissionScopeError,
    LLMService,
    ProviderConnectionNotFoundError,
    ProviderConnectionService,
    proxy_url_for,
)
from openhands.ev2.util.search_filter import AllSearchFilter

_USER_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")


async def _seed_user(
    session: AsyncSession,
    *,
    email: str = "svc@example.com",
    username: str = "svc",
) -> uuid.UUID:
    user = await make_principal(session, email=email, username=username)
    await session.flush()
    return user.id


@pytest.fixture
def conn_service(session: AsyncSession) -> ProviderConnectionService:
    return ProviderConnectionService(session, AllSearchFilter[StoredProviderConnection]())


@pytest.fixture
def llm_service(session: AsyncSession) -> LLMService:
    return LLMService(session, AllSearchFilter[StoredLLM]())


async def _make_conn(
    service: ProviderConnectionService,
    user_id: uuid.UUID,
    *,
    api_key: str | None = "k",
    enable_proxy: bool = False,
    base_url: str | None = "https://real.example.com",
) -> StoredProviderConnection:
    return await service.create(
        ProviderConnectionCreate(
            display_name="c",
            provider="custom",
            api_key=api_key,
            base_url=base_url,
            enable_proxy=enable_proxy,
        ),
        user_id=user_id,
    )


class TestProviderConnectionService:
    async def test_create_and_get(self, conn_service: ProviderConnectionService) -> None:
        uid = await _seed_user(conn_service._session)
        conn = await _make_conn(conn_service, uid, api_key="secret")
        assert conn.api_key != "secret"  # encrypted
        fetched = await conn_service.get(conn.id)
        assert fetched.display_name == "c"

    async def test_create_api_key_none(self, conn_service: ProviderConnectionService) -> None:
        uid = await _seed_user(conn_service._session)
        conn = await _make_conn(conn_service, uid, api_key=None)
        assert conn.api_key is None

    async def test_update(self, conn_service: ProviderConnectionService) -> None:
        uid = await _seed_user(conn_service._session)
        conn = await _make_conn(conn_service, uid)
        updated = await conn_service.update(
            conn.id,
            ProviderConnectionUpdate(display_name="new", enable_proxy=True, api_key="rotated"),
        )
        assert updated.display_name == "new"
        assert updated.enable_proxy is True
        assert updated.api_key != "rotated"

    async def test_get_missing(self, conn_service: ProviderConnectionService) -> None:
        with pytest.raises(ProviderConnectionNotFoundError):
            await conn_service.get(uuid.uuid4())

    async def test_delete(self, conn_service: ProviderConnectionService) -> None:
        uid = await _seed_user(conn_service._session)
        conn = await _make_conn(conn_service, uid)
        await conn_service.delete(conn.id)
        with pytest.raises(ProviderConnectionNotFoundError):
            await conn_service.get(conn.id)

    async def test_search_pagination(self, conn_service: ProviderConnectionService) -> None:
        uid = await _seed_user(conn_service._session)
        for _ in range(3):
            await _make_conn(conn_service, uid)
        rows, next_cursor = await conn_service.search(limit=2)
        assert len(rows) == 2
        assert next_cursor is not None
        rows2, next_cursor2 = await conn_service.search(cursor=next_cursor, limit=2)
        assert len(rows2) == 1
        assert next_cursor2 is None


class TestLLMService:
    async def test_create_and_get(
        self,
        conn_service: ProviderConnectionService,
        llm_service: LLMService,
    ) -> None:
        uid = await _seed_user(conn_service._session)
        conn = await _make_conn(conn_service, uid)
        llm = await llm_service.create(
            LLMCreate(
                provider_connection_id=conn.id,
                model="gpt-4o",
                display_name="m",
                config={"num_retries": 2},
            ),
            user_id=uid,
        )
        assert llm.model == "gpt-4o"
        fetched = await llm_service.get(llm.id)
        assert fetched.config == {"num_retries": 2}

    async def test_create_invalid_connection(
        self,
        llm_service: LLMService,
    ) -> None:
        uid = await _seed_user(llm_service._session)
        with pytest.raises(LLMPermissionScopeError):
            await llm_service.create(
                LLMCreate(
                    provider_connection_id=uuid.uuid4(),
                    model="gpt-4o",
                    display_name="m",
                ),
                user_id=uid,
            )

    async def test_create_invalid_config(
        self,
        conn_service: ProviderConnectionService,
        llm_service: LLMService,
    ) -> None:
        uid = await _seed_user(conn_service._session)
        conn = await _make_conn(conn_service, uid)
        with pytest.raises(LLMConfigError):
            await llm_service.create(
                LLMCreate(
                    provider_connection_id=conn.id,
                    model="gpt-4o",
                    display_name="m",
                    # num_retries is `ge=0` -> -1 is invalid for the SDK LLM.
                    config={"num_retries": -1},
                ),
                user_id=uid,
            )

    async def test_update(self, conn_service, llm_service) -> None:
        uid = await _seed_user(conn_service._session)
        conn = await _make_conn(conn_service, uid)
        llm = await llm_service.create(
            LLMCreate(provider_connection_id=conn.id, model="gpt-4o", display_name="m"),
            user_id=uid,
        )
        updated = await llm_service.update(
            llm.id, LLMUpdate(display_name="renamed", config={"temperature": 0.1})
        )
        assert updated.display_name == "renamed"
        assert updated.config == {"temperature": 0.1}

    async def test_delete(self, conn_service, llm_service) -> None:
        uid = await _seed_user(conn_service._session)
        conn = await _make_conn(conn_service, uid)
        llm = await llm_service.create(
            LLMCreate(provider_connection_id=conn.id, model="gpt-4o", display_name="m"),
            user_id=uid,
        )
        await llm_service.delete(llm.id)
        with pytest.raises(LLMNotFoundError):
            await llm_service.get(llm.id)

    async def test_materialize_llm(
        self,
        conn_service: ProviderConnectionService,
        llm_service: LLMService,
    ) -> None:
        uid = await _seed_user(conn_service._session)
        conn = await _make_conn(conn_service, uid, enable_proxy=True)
        llm = await llm_service.create(
            LLMCreate(provider_connection_id=conn.id, model="gpt-4o", display_name="m"),
            user_id=uid,
        )
        sdk_llm = await llm_service.materialize_llm(llm)
        assert sdk_llm.model == "gpt-4o"
        # enable_proxy -> base_url is the proxy URL, keyed on the LLM id.
        assert str(llm.id) in sdk_llm.base_url

        direct_llm = await llm_service.materialize_llm(llm, use_proxy=False)
        assert direct_llm.base_url == "https://real.example.com"

    async def test_connection_for_llm(
        self,
        conn_service: ProviderConnectionService,
        llm_service: LLMService,
    ) -> None:
        uid = await _seed_user(conn_service._session)
        conn = await _make_conn(conn_service, uid)
        llm = await llm_service.create(
            LLMCreate(provider_connection_id=conn.id, model="gpt-4o", display_name="m"),
            user_id=uid,
        )
        resolved = await llm_service.connection_for_llm(llm)
        assert resolved.id == conn.id

    async def test_connection_for_llm_missing_raises(
        self,
        conn_service: ProviderConnectionService,
        llm_service: LLMService,
    ) -> None:
        uid = await _seed_user(conn_service._session)
        conn = await _make_conn(conn_service, uid)
        llm = await llm_service.create(
            LLMCreate(provider_connection_id=conn.id, model="gpt-4o", display_name="m"),
            user_id=uid,
        )
        # Re-point the LLM at a connection owned by a different user: the
        # connection exists but its owner no longer matches the LLM's owner.
        other_uid = await _seed_user(
            conn_service._session, email="other@example.com", username="other"
        )
        other_conn = await _make_conn(conn_service, other_uid)
        llm.provider_connection_id = other_conn.id
        with pytest.raises(LLMNotFoundError):
            await llm_service.connection_for_llm(llm)


class TestProxyUrl:
    def test_built_from_config(self) -> None:
        url = proxy_url_for(uuid.UUID("00000000-0000-0000-0000-000000000000"))
        assert url.endswith("/llm/completion/00000000-0000-0000-0000-000000000000")
