"""Unit tests for the retrieval-oriented secret-value projection.

Exercises the :class:`SecretProvider` ABC, the ``kind="static"``
implementation (:class:`StaticSecretProvider`), the provider registry/cache,
and the :class:`SecretValueSession` reveal service (AGENTS.md §12).
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession
from tests.unit._auth_helpers import make_principal

from openhands.ev2.secret.secret_models import SecretProvider, StaticSecret
from openhands.ev2.secret.secret_provider import (
    SecretProvider as SecretProviderABC,
)
from openhands.ev2.secret.secret_provider_service import SecretProviderService
from openhands.ev2.secret.secret_schemas import SecretProviderCreate, StaticSecretCreate
from openhands.ev2.secret.secret_value import SecretValue
from openhands.ev2.secret.secret_value_service import (
    SecretValueNotFoundError,
    SecretValueSession,
)
from openhands.ev2.secret.static_secret_provider import StaticSecretProvider
from openhands.ev2.secret.static_secret_service import StaticSecretService
from openhands.ev2.util.search_filter import AllSearchFilter, NoneSearchFilter

OWNER_EMAIL = "owner@example.com"


async def _seed_user(
    session: AsyncSession,
    *,
    email: str = OWNER_EMAIL,
    username: str = "owner",
) -> uuid.UUID:
    user = await make_principal(session, email=email, username=username)
    await session.flush()
    return user.id


async def _seed_provider_and_secret(session: AsyncSession) -> tuple[uuid.UUID, uuid.UUID]:
    user_id = await _seed_user(session)

    provider = await SecretProviderService(session, AllSearchFilter[SecretProvider]()).create(
        SecretProviderCreate(kind="static", data={"vault": "test"}), creator_id=user_id
    )

    secret = await StaticSecretService(session, AllSearchFilter[StaticSecret]()).create(
        StaticSecretCreate(name="API_KEY", value="s3cr3t"), creator_id=user_id
    )

    await session.flush()
    return provider.id, secret.id


def _static_provider() -> StaticSecretProvider:
    from openhands.ev2.encryption.encryption_service import get_encryption_service

    return StaticSecretProvider(get_encryption_service())


class TestSecretValueSplit:
    def test_make_and_split_roundtrip(self) -> None:
        pid = uuid.uuid4()
        value = SecretValue.make(
            provider_id=pid,
            internal_id="abc-123",
            name="TOKEN",
            value="plaintext",
        )
        assert value.id == f"{pid}/abc-123"
        parsed_provider, parsed_internal = SecretValue.split_id(value.id)
        assert parsed_provider == pid
        assert parsed_internal == "abc-123"

    def test_split_rejects_malformed(self) -> None:
        with pytest.raises(ValueError):
            SecretValue.split_id("not-a-uuid/x")
        with pytest.raises(ValueError):
            SecretValue.split_id("no-slash")
        with pytest.raises(ValueError):
            SecretValue.split_id(f"{uuid.uuid4()}/")

    def test_invalid_name_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SecretValue.make(
                provider_id=uuid.uuid4(),
                internal_id="i",
                name="lower",
                value="v",
            )


class TestStaticSecretProvider:
    async def test_get_roundtrip_decrypts(self, session: AsyncSession) -> None:
        provider_id, secret_id = await _seed_provider_and_secret(session)
        provider = _static_provider()

        value = await provider.get(session, provider_id, str(secret_id))
        assert value is not None
        assert value.name == "API_KEY"
        assert value.value == "s3cr3t"
        assert value.provider_id == provider_id
        assert value.internal_id == str(secret_id)

        # A valid UUID with no row yields None.
        assert await provider.get(session, provider_id, str(uuid.uuid4())) is None
        # A malformed internal id yields None.
        assert await provider.get(session, provider_id, "not-a-uuid") is None

    async def test_batch_get(self, session: AsyncSession) -> None:
        provider_id, secret_id = await _seed_provider_and_secret(session)
        provider = _static_provider()

        missing = uuid.uuid4()
        values = await provider.batch_get(
            session,
            [provider_id, provider_id, provider_id],
            [str(secret_id), str(missing), "bad"],
        )
        assert [v.value if v else None for v in values] == ["s3cr3t", None, None]
        assert await provider.batch_get(session, [], []) == []

    async def test_batch_get_length_mismatch_rejected(self, session: AsyncSession) -> None:
        provider = _static_provider()
        with pytest.raises(ValueError):
            await provider.batch_get(session, [uuid.uuid4()], ["a", "b"])

    async def test_search_pages(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        provider = await SecretProviderService(session, AllSearchFilter[SecretProvider]()).create(
            SecretProviderCreate(kind="static"), creator_id=user_id
        )
        svc = StaticSecretService(session, AllSearchFilter[StaticSecret]())
        for i in range(3):
            await svc.create(
                StaticSecretCreate(name=f"KEY_{i}", value=f"value-{i}"), creator_id=user_id
            )

        impl = _static_provider()
        page, next_cursor = await impl.search(session, provider.id, limit=2)
        assert len(page) == 2
        assert next_cursor is not None

        page2, next_cursor2 = await impl.search(session, provider.id, limit=2, cursor=next_cursor)
        assert len(page2) == 1
        assert next_cursor2 is None

        assert sorted(v.name for v in page + page2) == ["KEY_0", "KEY_1", "KEY_2"]


class TestSecretValueSession:
    async def test_get_reveals_plaintext(self, session: AsyncSession) -> None:
        provider_id, secret_id = await _seed_provider_and_secret(session)
        service = SecretValueSession(session)

        value = await service.get(
            f"{provider_id}/{secret_id}",
            AllSearchFilter[SecretProvider](),
        )
        assert value.value == "s3cr3t"
        assert value.provider_id == provider_id
        assert value.internal_id == str(secret_id)

    async def test_get_malformed_composite_raises(self, session: AsyncSession) -> None:
        service = SecretValueSession(session)
        with pytest.raises(SecretValueNotFoundError):
            await service.get("not-a-composite", AllSearchFilter[SecretProvider]())

    async def test_get_missing_provider_raises(self, session: AsyncSession) -> None:
        service = SecretValueSession(session)
        with pytest.raises(SecretValueNotFoundError):
            await service.get(f"{uuid.uuid4()}/nope", AllSearchFilter[SecretProvider]())

    async def test_get_missing_internal_id_raises(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        provider = await SecretProviderService(session, AllSearchFilter[SecretProvider]()).create(
            SecretProviderCreate(kind="static"), creator_id=user_id
        )

        service = SecretValueSession(session)
        # The provider exists but the composite internal id maps to no row.
        with pytest.raises(SecretValueNotFoundError):
            await service.get(
                f"{provider.id}/{uuid.uuid4()}",
                AllSearchFilter[SecretProvider](),
            )

    async def test_get_denied_provider_raises(self, session: AsyncSession) -> None:
        provider_id, secret_id = await _seed_provider_and_secret(session)
        service = SecretValueSession(session)
        with pytest.raises(SecretValueNotFoundError):
            await service.get(
                f"{provider_id}/{secret_id}",
                NoneSearchFilter[SecretProvider](),
            )

    async def test_get_many_aligns_and_filters(self, session: AsyncSession) -> None:
        provider_id, secret_id = await _seed_provider_and_secret(session)
        service = SecretValueSession(session)

        good = f"{provider_id}/{secret_id}"
        malformed = "junk/id"
        missing_provider = f"{uuid.uuid4()}/whatever"
        values = await service.get_many(
            [good, malformed, missing_provider],
            AllSearchFilter[SecretProvider](),
        )
        assert values[0] is not None and values[0].value == "s3cr3t"
        assert values[1] is None
        assert values[2] is None
        assert await service.get_many([], AllSearchFilter[SecretProvider]()) == []

    async def test_search_by_provider(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        provider = await SecretProviderService(session, AllSearchFilter[SecretProvider]()).create(
            SecretProviderCreate(kind="static"), creator_id=user_id
        )
        svc = StaticSecretService(session, AllSearchFilter[StaticSecret]())
        for i in range(3):
            await svc.create(
                StaticSecretCreate(name=f"KEY_{i}", value=f"value-{i}"), creator_id=user_id
            )

        service = SecretValueSession(session)
        values, next_cursor = await service.search(
            provider.id, AllSearchFilter[SecretProvider](), limit=2
        )
        assert len(values) == 2
        assert next_cursor is not None

        values2, next_cursor2 = await service.search(
            provider.id, AllSearchFilter[SecretProvider](), limit=2, cursor=next_cursor
        )
        assert len(values2) == 1
        assert next_cursor2 is None

        all_names = sorted(v.name for v in values + values2)
        assert all_names == ["KEY_0", "KEY_1", "KEY_2"]

    async def test_search_denied_provider_raises(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        provider = await SecretProviderService(session, AllSearchFilter[SecretProvider]()).create(
            SecretProviderCreate(kind="static"), creator_id=user_id
        )
        service = SecretValueSession(session)
        with pytest.raises(SecretValueNotFoundError):
            await service.search(
                provider.id,
                NoneSearchFilter[SecretProvider](),
                limit=5,
            )


async def _seed_oauth_provider_and_session(
    session: AsyncSession,
) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
    """Seed an oauth-kind SecretProvider + OAuthProvider + OAuthSession.

    Returns ``(secret_provider_id, oauth_provider_id, oauth_session_id)``.
    """
    from datetime import UTC, datetime, timedelta

    from openhands.ev2.encryption.encryption_service import get_encryption_service
    from openhands.ev2.oauth.oauth_provider_models import OAuthProvider
    from openhands.ev2.oauth.oauth_session_models import OAuthSession

    user_id = await _seed_user(session, email="oauth-sv-test@example.com", username="oauth-sv-test")
    enc = get_encryption_service()
    now = datetime.now(UTC)

    sp = await SecretProviderService(session, AllSearchFilter[SecretProvider]()).create(
        SecretProviderCreate(kind="oauth", data={}), creator_id=user_id
    )
    oauth_provider = OAuthProvider(
        name="github-sv-test",
        creator_id=user_id,
        url="https://github.com/login/oauth",
        client_id="cid",
        client_secret=enc.encrypt_value("secret"),
        scopes=["repo"],
        expire_drift_tolerance=60,
        access_token_expires_in=900,
        refresh_token_expires_in=2_592_000,
    )
    session.add(oauth_provider)
    await session.flush()
    oauth_session = OAuthSession(
        oauth_provider_id=oauth_provider.id,
        creator_id=user_id,
        access_token=enc.encrypt_value("ghp_svtest"),
        refresh_token=enc.encrypt_value("refresh_svtest"),
        access_token_expires_at=now + timedelta(hours=1),
        refresh_token_expires_at=now + timedelta(days=30),
    )
    session.add(oauth_session)
    await session.flush()
    return sp.id, oauth_provider.id, oauth_session.id


class TestOAuthSessionUseEnforcement:
    """Per-session USE filter enforcement for oauth-kind secrets (issue #141)."""

    async def test_get_no_session_filter_raises(self, session: AsyncSession) -> None:
        sp_id, op_id, os_id = await _seed_oauth_provider_and_session(session)
        service = SecretValueSession(session)
        with pytest.raises(SecretValueNotFoundError):
            await service.get(
                f"{sp_id}/{op_id}/{os_id}",
                AllSearchFilter[SecretProvider](),
            )

    async def test_get_none_session_filter_raises(self, session: AsyncSession) -> None:
        sp_id, op_id, os_id = await _seed_oauth_provider_and_session(session)
        service = SecretValueSession(session)
        with pytest.raises(SecretValueNotFoundError):
            await service.get(
                f"{sp_id}/{op_id}/{os_id}",
                AllSearchFilter[SecretProvider](),
                session_filter=NoneSearchFilter[Any](),
            )

    async def test_get_all_session_filter_succeeds(self, session: AsyncSession) -> None:
        sp_id, op_id, os_id = await _seed_oauth_provider_and_session(session)
        service = SecretValueSession(session)
        value = await service.get(
            f"{sp_id}/{op_id}/{os_id}",
            AllSearchFilter[SecretProvider](),
            session_filter=AllSearchFilter[Any](),
        )
        assert value is not None
        assert value.value == "ghp_svtest"

    async def test_get_many_filters_unauthorized_oauth(self, session: AsyncSession) -> None:
        sp_id, op_id, os_id = await _seed_oauth_provider_and_session(session)
        service = SecretValueSession(session)
        composite = f"{sp_id}/{op_id}/{os_id}"
        values = await service.get_many(
            [composite],
            AllSearchFilter[SecretProvider](),
            session_filter=NoneSearchFilter[Any](),
        )
        assert len(values) == 1
        assert values[0] is None

    async def test_get_many_allows_authorized_oauth(self, session: AsyncSession) -> None:
        sp_id, op_id, os_id = await _seed_oauth_provider_and_session(session)
        service = SecretValueSession(session)
        composite = f"{sp_id}/{op_id}/{os_id}"
        values = await service.get_many(
            [composite],
            AllSearchFilter[SecretProvider](),
            session_filter=AllSearchFilter[Any](),
        )
        assert len(values) == 1
        assert values[0] is not None
        assert values[0].value == "ghp_svtest"

    async def test_search_no_session_filter_returns_empty(self, session: AsyncSession) -> None:
        sp_id, _, _ = await _seed_oauth_provider_and_session(session)
        service = SecretValueSession(session)
        values, next_cursor = await service.search(
            sp_id,
            AllSearchFilter[SecretProvider](),
            limit=10,
        )
        assert values == []
        assert next_cursor is None

    async def test_search_none_session_filter_returns_empty(self, session: AsyncSession) -> None:
        sp_id, _, _ = await _seed_oauth_provider_and_session(session)
        service = SecretValueSession(session)
        values, next_cursor = await service.search(
            sp_id,
            AllSearchFilter[SecretProvider](),
            limit=10,
            session_filter=NoneSearchFilter[Any](),
        )
        assert values == []
        assert next_cursor is None

    async def test_search_all_session_filter_returns_values(self, session: AsyncSession) -> None:
        sp_id, _, _ = await _seed_oauth_provider_and_session(session)
        service = SecretValueSession(session)
        values, _ = await service.search(
            sp_id,
            AllSearchFilter[SecretProvider](),
            limit=10,
            session_filter=AllSearchFilter[Any](),
        )
        assert len(values) >= 1
        assert any(v.value == "ghp_svtest" for v in values)


class _StubClient:
    """Provider client used to test the registry cache lifecycle."""

    def __init__(self) -> None:
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True


class _StubProvider(SecretProviderABC):
    """Minimal provider implementation used to exercise registry caching."""

    def __init__(self, client: _StubClient) -> None:
        self._client = client

    async def get(
        self,
        session: AsyncSession,
        provider_id: uuid.UUID,
        internal_id: str,
    ) -> SecretValue | None:
        return None

    async def batch_get(
        self,
        session: AsyncSession,
        provider_ids: list[uuid.UUID],
        internal_ids: list[str],
    ) -> list[SecretValue | None]:
        return [None] * len(provider_ids)

    async def search(
        self,
        session: AsyncSession,
        provider_id: uuid.UUID,
        *,
        limit: int,
        cursor: str | None = None,
    ) -> tuple[list[SecretValue], str | None]:
        return [], None

    async def aclose(self) -> None:
        await self._client.aclose()


class TestProviderRegistry:
    def test_unknown_kind_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from openhands.ev2.config import get_config
        from openhands.ev2.encryption.encryption_service import get_encryption_service
        from openhands.ev2.secret.secret_provider_registry import SecretProviderCache

        get_config.cache_clear()
        get_encryption_service.cache_clear()
        monkeypatch.setenv("OHE_ENCRYPTION_KEY_VALUE", "test-secret")
        cache = SecretProviderCache(get_encryption_service())
        with pytest.raises(ValueError):
            cache.get(uuid.uuid4(), "aws_sm", {})
        get_encryption_service.cache_clear()

    async def test_cache_constructs_once_and_aclose_is_safe(self) -> None:
        from openhands.ev2.secret.secret_provider_registry import (
            SecretProviderCache,
            register_provider_factory,
        )

        registry_clients: list[_StubClient] = []
        probe = _StubClient()

        def factory(data: dict[str, object], enc=None) -> _StubProvider:
            registry_clients.append(probe)
            return _StubProvider(probe)

        register_provider_factory("stub-test", factory)
        cache = SecretProviderCache(None)  # type: ignore[arg-type]
        pid = uuid.uuid4()

        first = cache.get(pid, "stub-test", {})
        second = cache.get(pid, "stub-test", {})
        assert first is second
        # A different provider id constructs a fresh client.
        cache.get(uuid.uuid4(), "stub-test", {})
        assert len(registry_clients) == 2

        await cache.aclose()
        assert probe.closed
        # A second close is a safe no-op.
        await cache.aclose()
