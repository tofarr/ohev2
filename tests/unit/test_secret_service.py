"""Unit tests for the SecretService and SecretValueService (DB-backed)."""

from __future__ import annotations

import uuid

import pytest
from pydantic import SecretStr, ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.encryption.encryption_service import EncryptionService, get_encryption_service
from openhands.ev2.secret.secret_models import (
    Secret,
    SecretType,
    StaticSecretDetail,
)
from openhands.ev2.secret.secret_schemas import (
    SecretBatchCreate,
    SecretBatchDelete,
    SecretBatchUpdate,
    SecretCreate,
    SecretRead,
    SecretUpdate,
)
from openhands.ev2.secret.secret_service import (
    BatchPermissionDeniedError,
    SecretCodeConflictError,
    SecretNotFoundError,
    SecretPermissionScopeError,
    SecretService,
    SecretValueNotFoundError,
    SecretValueService,
    SecretValueTypeError,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.user.user_models import User
from openhands.ev2.util.search_filter import AllSearchFilter, NoneSearchFilter


@pytest.fixture
def enc() -> EncryptionService:
    return get_encryption_service()


@pytest.fixture
def service(session: AsyncSession, enc: EncryptionService) -> SecretService:
    return SecretService(session, AllSearchFilter[Secret](), encryption_service=enc)


async def _seed_user(session: AsyncSession, *, n: int = 0) -> User:
    user = User(email=f"s{n}@example.com", username=f"su{n}")
    session.add(user)
    await session.flush()
    return user


async def _static_detail(session: AsyncSession, secret_id: uuid.UUID) -> StaticSecretDetail | None:
    result = await session.execute(
        select(StaticSecretDetail).where(StaticSecretDetail.secret_id == secret_id)
    )
    return result.scalar_one_or_none()


class TestCreate:
    async def test_create_encrypts_value(
        self, service: SecretService, session: AsyncSession, enc: EncryptionService
    ) -> None:
        user = await _seed_user(session)
        secret = await service.create(
            SecretCreate(code="API_KEY", value=SecretStr("hunter2")),
            creator_id=user.id,
        )
        assert secret.code == "API_KEY"
        assert secret.type == SecretType.STATIC
        # The persisted ciphertext lives in the detail row, never on the secret.
        detail = await _static_detail(session, secret.id)
        assert detail is not None
        assert detail.value != "hunter2"
        assert enc.decrypt_value(detail.value) == "hunter2"
        assert secret.creator_id == user.id

    async def test_create_duplicate_code_conflicts(
        self, service: SecretService, session: AsyncSession
    ) -> None:
        user = await _seed_user(session)
        await service.create(SecretCreate(code="DUP", value=SecretStr("v")), creator_id=user.id)
        with pytest.raises(SecretCodeConflictError):
            await service.create(
                SecretCreate(code="DUP", value=SecretStr("v2")), creator_id=user.id
            )

    async def test_create_scope_denied(self, session: AsyncSession, enc: EncryptionService) -> None:
        user = await _seed_user(session)
        svc = SecretService(session, NoneSearchFilter[Secret](), encryption_service=enc)
        with pytest.raises(SecretPermissionScopeError):
            await svc.create(SecretCreate(code="X", value=SecretStr("v")), creator_id=user.id)


class TestRead:
    async def test_get_returns_secret(self, service: SecretService, session: AsyncSession) -> None:
        user = await _seed_user(session)
        secret = await service.create(
            SecretCreate(code="G", value=SecretStr("plain")), creator_id=user.id
        )
        fetched = await service.get(secret.id)
        assert fetched.id == secret.id

    async def test_get_missing_raises(self, service: SecretService) -> None:
        with pytest.raises(SecretNotFoundError):
            await service.get(uuid.uuid4())

    async def test_get_out_of_scope_raises(
        self, session: AsyncSession, enc: EncryptionService
    ) -> None:
        user = await _seed_user(session)
        admin = SecretService(session, AllSearchFilter[Secret](), encryption_service=enc)
        secret = await admin.create(
            SecretCreate(code="OOS", value=SecretStr("v")), creator_id=user.id
        )
        scoped = SecretService(session, NoneSearchFilter[Secret](), encryption_service=enc)
        with pytest.raises(SecretNotFoundError):
            await scoped.get(secret.id)

    async def test_to_read_omits_value(self, service: SecretService, session: AsyncSession) -> None:
        user = await _seed_user(session)
        secret = await service.create(
            SecretCreate(code="R", value=SecretStr("reveal-me")), creator_id=user.id
        )
        read = service.to_read(secret)
        assert read.code == "R"
        assert read.type == SecretType.STATIC
        # SecretRead must not carry a value field at all.
        assert "value" not in SecretRead.model_fields


class TestUpdate:
    async def test_update_value_re_encrypts(
        self, service: SecretService, session: AsyncSession, enc: EncryptionService
    ) -> None:
        user = await _seed_user(session)
        secret = await service.create(
            SecretCreate(code="U", value=SecretStr("old")), creator_id=user.id
        )
        detail = await _static_detail(session, secret.id)
        assert detail is not None
        old_cipher = detail.value
        await service.update(secret.id, SecretUpdate(value=SecretStr("new")))
        refreshed = await _static_detail(session, secret.id)
        assert refreshed is not None
        assert refreshed.value != old_cipher
        assert enc.decrypt_value(refreshed.value) == "new"

    async def test_update_code_conflict(
        self, service: SecretService, session: AsyncSession
    ) -> None:
        user = await _seed_user(session)
        await service.create(SecretCreate(code="KEEP", value=SecretStr("v")), creator_id=user.id)
        other = await service.create(
            SecretCreate(code="ORIG", value=SecretStr("v")), creator_id=user.id
        )
        with pytest.raises(SecretCodeConflictError):
            await service.update(other.id, SecretUpdate(code="KEEP"))

    async def test_update_missing_raises(self, service: SecretService) -> None:
        with pytest.raises(SecretNotFoundError):
            await service.update(uuid.uuid4(), SecretUpdate(code="x"))

    async def test_update_value_on_oauth_raises_type_error(
        self, service: SecretService, session: AsyncSession
    ) -> None:
        secret = Secret(code="OAUTH_SECRET", type="oauth")  # type: ignore[arg-type]
        session.add(secret)
        await session.flush()
        with pytest.raises(SecretValueTypeError):
            await service.update(secret.id, SecretUpdate(value=SecretStr("v")))


class TestDelete:
    async def test_delete_removes(self, service: SecretService, session: AsyncSession) -> None:
        user = await _seed_user(session)
        secret = await service.create(
            SecretCreate(code="DEL", value=SecretStr("v")), creator_id=user.id
        )
        await service.delete(secret.id)
        with pytest.raises(SecretNotFoundError):
            await service.get(secret.id)

    async def test_delete_missing_raises(self, service: SecretService) -> None:
        with pytest.raises(SecretNotFoundError):
            await service.delete(uuid.uuid4())


class TestBatch:
    async def test_batch_mixed_ops(
        self, service: SecretService, session: AsyncSession, enc: EncryptionService
    ) -> None:
        user = await _seed_user(session)
        created = await service.create(
            SecretCreate(code="B1", value=SecretStr("v")), creator_id=user.id
        )
        ops = [
            SecretBatchCreate(data=SecretCreate(code="B2", value=SecretStr("v2"))),
            SecretBatchUpdate(id=created.id, data=SecretUpdate(description="updated")),
            SecretBatchDelete(id=created.id),
        ]
        filters = {
            a: AllSearchFilter[Secret]() for a in (Action.CREATE, Action.UPDATE, Action.DELETE)
        }
        results = await service.apply_batch(ops, filters, creator_id=user.id)
        assert results[0] is not None and results[0].code == "B2"
        assert results[1] is not None and results[1].description == "updated"
        assert results[2] is None

    async def test_batch_denied_when_action_filter_none(
        self, service: SecretService, session: AsyncSession
    ) -> None:
        user = await _seed_user(session)
        ops = [SecretBatchCreate(data=SecretCreate(code="BD", value=SecretStr("v")))]
        with pytest.raises(BatchPermissionDeniedError):
            await service.apply_batch(ops, {Action.CREATE: None}, creator_id=user.id)


class TestCountAndSearch:
    async def test_count_and_search(self, service: SecretService, session: AsyncSession) -> None:
        user = await _seed_user(session)
        for i in range(3):
            await service.create(
                SecretCreate(code=f"C{i}", value=SecretStr("v")), creator_id=user.id
            )
        assert await service.count() == 3
        secrets, nxt = await service.search_secrets(limit=2)
        assert len(secrets) == 2
        assert nxt is not None
        rest, nxt2 = await service.search_secrets(cursor=nxt, limit=2)
        assert len(rest) == 1
        assert nxt2 is None


class TestSecretValueService:
    """Reveal requires both read-access and value-reveal filters."""

    @pytest.fixture
    def value_service(self, session: AsyncSession, enc: EncryptionService) -> SecretValueService:
        return SecretValueService(
            session,
            AllSearchFilter[Secret](),
            AllSearchFilter[Secret](),
            encryption_service=enc,
        )

    async def test_reveal_returns_plaintext(
        self, value_service: SecretValueService, service: SecretService, session: AsyncSession
    ) -> None:
        user = await _seed_user(session)
        secret = await service.create(
            SecretCreate(code="RV", value=SecretStr("reveal-me")), creator_id=user.id
        )
        read = await value_service.get(secret.id)
        assert read.value == "reveal-me"
        assert read.code == "RV"
        assert read.type.value == "static"

    async def test_reveal_denied_without_read_access(
        self, service: SecretService, session: AsyncSession, enc: EncryptionService
    ) -> None:
        user = await _seed_user(session)
        secret = await service.create(
            SecretCreate(code="NO_READ", value=SecretStr("v")), creator_id=user.id
        )
        svc = SecretValueService(
            session,
            NoneSearchFilter[Secret](),  # no read access
            AllSearchFilter[Secret](),  # value permission present
            encryption_service=enc,
        )
        with pytest.raises(SecretValueNotFoundError):
            await svc.get(secret.id)

    async def test_reveal_denied_without_value_permission(
        self, service: SecretService, session: AsyncSession, enc: EncryptionService
    ) -> None:
        user = await _seed_user(session)
        secret = await service.create(
            SecretCreate(code="NO_VAL", value=SecretStr("v")), creator_id=user.id
        )
        svc = SecretValueService(
            session,
            AllSearchFilter[Secret](),  # read access present
            NoneSearchFilter[Secret](),  # no value permission
            encryption_service=enc,
        )
        with pytest.raises(SecretValueNotFoundError):
            await svc.get(secret.id)

    async def test_reveal_missing_detail_raises(
        self, session: AsyncSession, enc: EncryptionService
    ) -> None:
        # A static secret with no detail row is a data integrity break.
        secret = Secret(code="NO_DETAIL")
        session.add(secret)
        await session.flush()
        svc = SecretValueService(
            session,
            AllSearchFilter[Secret](),
            AllSearchFilter[Secret](),
            encryption_service=enc,
        )
        with pytest.raises(SecretValueNotFoundError):
            await svc.get(secret.id)

    async def test_reveal_oauth_without_detail_raises(
        self, session: AsyncSession, enc: EncryptionService
    ) -> None:
        secret = Secret(code="OAUTH_ND", type="oauth")  # type: ignore[arg-type]
        session.add(secret)
        await session.flush()
        svc = SecretValueService(
            session,
            AllSearchFilter[Secret](),
            AllSearchFilter[Secret](),
            encryption_service=enc,
        )
        with pytest.raises(SecretValueNotFoundError):
            await svc.get(secret.id)

    async def test_get_many_positional(
        self, value_service: SecretValueService, service: SecretService, session: AsyncSession
    ) -> None:
        user = await _seed_user(session)
        a = await service.create(
            SecretCreate(code="GM_A", value=SecretStr("a")), creator_id=user.id
        )
        b = await service.create(
            SecretCreate(code="GM_B", value=SecretStr("b")), creator_id=user.id
        )
        results = await value_service.get_many([a.id, b.id, uuid.uuid4()])
        assert results[0] is not None and results[0].value == "a"
        assert results[1] is not None and results[1].value == "b"
        assert results[2] is None


class TestSecretSchemaValidation:
    """Pure schema-level validation for SecretCreate/SecretUpdate."""

    def test_create_rejects_whitespace_only_code(self) -> None:
        with pytest.raises(ValidationError):
            SecretCreate(code="   ", value=SecretStr("v"))

    def test_create_requires_value_for_static(self) -> None:
        with pytest.raises(ValidationError, match="value is required when type is static"):
            SecretCreate(code="S", type="static")  # type: ignore[arg-type]

    def test_create_rejects_value_for_oauth(self) -> None:
        with pytest.raises(ValidationError, match="value is not allowed for type oauth"):
            SecretCreate(code="O", type="oauth", value=SecretStr("v"))  # type: ignore[arg-type]

    def test_create_oauth_without_value_succeeds(self) -> None:
        payload = SecretCreate(code="O", type="oauth")  # type: ignore[arg-type]
        assert payload.value is None

    def test_update_none_code_passes_through(self) -> None:
        assert SecretUpdate().code is None

    def test_update_rejects_whitespace_only_code(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            SecretUpdate(code="   ")

    def test_update_rejects_invalid_code_chars(self) -> None:
        with pytest.raises(ValueError, match="letters, digits"):
            SecretUpdate(code="bad!")
