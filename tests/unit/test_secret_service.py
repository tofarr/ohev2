"""Unit tests for the SecretService (DB-backed, encryption round-trip)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.encryption.encryption_service import EncryptionService, get_encryption_service
from openhands.ev2.secret.secret_models import Secret
from openhands.ev2.secret.secret_schemas import (
    SecretBatchCreate,
    SecretBatchDelete,
    SecretBatchUpdate,
    SecretCreate,
    SecretUpdate,
)
from openhands.ev2.secret.secret_service import (
    BatchPermissionDeniedError,
    SecretCodeConflictError,
    SecretNotFoundError,
    SecretPermissionScopeError,
    SecretService,
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


class TestCreate:
    async def test_create_encrypts_value(
        self, service: SecretService, session: AsyncSession, enc: EncryptionService
    ) -> None:
        from pydantic import SecretStr

        user = await _seed_user(session)
        secret = await service.create(
            SecretCreate(code="API_KEY", value=SecretStr("hunter2")),
            user_id=user.id,
        )
        assert secret.code == "API_KEY"
        # The persisted value is ciphertext, never the plaintext.
        assert secret.value != "hunter2"
        assert enc.decrypt_value(secret.value) == "hunter2"
        assert secret.user_id == user.id

    async def test_create_duplicate_code_conflicts(
        self, service: SecretService, session: AsyncSession
    ) -> None:
        from pydantic import SecretStr

        user = await _seed_user(session)
        await service.create(SecretCreate(code="DUP", value=SecretStr("v")), user_id=user.id)
        with pytest.raises(SecretCodeConflictError):
            await service.create(SecretCreate(code="DUP", value=SecretStr("v2")), user_id=user.id)

    async def test_create_scope_denied(self, session: AsyncSession, enc: EncryptionService) -> None:
        from pydantic import SecretStr

        user = await _seed_user(session)
        svc = SecretService(session, NoneSearchFilter[Secret](), encryption_service=enc)
        with pytest.raises(SecretPermissionScopeError):
            await svc.create(SecretCreate(code="X", value=SecretStr("v")), user_id=user.id)


class TestRead:
    async def test_get_returns_secret(self, service: SecretService, session: AsyncSession) -> None:
        from pydantic import SecretStr

        user = await _seed_user(session)
        secret = await service.create(
            SecretCreate(code="G", value=SecretStr("plain")), user_id=user.id
        )
        fetched = await service.get(secret.id)
        assert fetched.id == secret.id

    async def test_get_missing_raises(self, service: SecretService) -> None:
        with pytest.raises(SecretNotFoundError):
            await service.get(uuid.uuid4())

    async def test_get_out_of_scope_raises(
        self, session: AsyncSession, enc: EncryptionService
    ) -> None:
        from pydantic import SecretStr

        user = await _seed_user(session)
        admin = SecretService(session, AllSearchFilter[Secret](), encryption_service=enc)
        secret = await admin.create(SecretCreate(code="OOS", value=SecretStr("v")), user_id=user.id)
        scoped = SecretService(session, NoneSearchFilter[Secret](), encryption_service=enc)
        with pytest.raises(SecretNotFoundError):
            await scoped.get(secret.id)

    async def test_to_read_decrypts_value(
        self, service: SecretService, session: AsyncSession
    ) -> None:
        from pydantic import SecretStr

        user = await _seed_user(session)
        secret = await service.create(
            SecretCreate(code="R", value=SecretStr("reveal-me")), user_id=user.id
        )
        read = service.to_read(secret)
        assert read.value == "reveal-me"
        assert read.code == "R"


class TestUpdate:
    async def test_update_value_re_encrypts(
        self, service: SecretService, session: AsyncSession, enc: EncryptionService
    ) -> None:
        from pydantic import SecretStr

        user = await _seed_user(session)
        secret = await service.create(
            SecretCreate(code="U", value=SecretStr("old")), user_id=user.id
        )
        old_cipher = secret.value
        updated = await service.update(secret.id, SecretUpdate(value=SecretStr("new")))
        assert updated.value != old_cipher
        assert enc.decrypt_value(updated.value) == "new"

    async def test_update_code_conflict(
        self, service: SecretService, session: AsyncSession
    ) -> None:
        from pydantic import SecretStr

        user = await _seed_user(session)
        await service.create(SecretCreate(code="KEEP", value=SecretStr("v")), user_id=user.id)
        other = await service.create(
            SecretCreate(code="ORIG", value=SecretStr("v")), user_id=user.id
        )
        with pytest.raises(SecretCodeConflictError):
            await service.update(other.id, SecretUpdate(code="KEEP"))

    async def test_update_missing_raises(self, service: SecretService) -> None:
        with pytest.raises(SecretNotFoundError):
            await service.update(uuid.uuid4(), SecretUpdate(code="x"))


class TestDelete:
    async def test_delete_removes(self, service: SecretService, session: AsyncSession) -> None:
        from pydantic import SecretStr

        user = await _seed_user(session)
        secret = await service.create(
            SecretCreate(code="DEL", value=SecretStr("v")), user_id=user.id
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
        from pydantic import SecretStr

        user = await _seed_user(session)
        created = await service.create(
            SecretCreate(code="B1", value=SecretStr("v")), user_id=user.id
        )
        ops = [
            SecretBatchCreate(data=SecretCreate(code="B2", value=SecretStr("v2"))),
            SecretBatchUpdate(id=created.id, data=SecretUpdate(description="updated")),
            SecretBatchDelete(id=created.id),
        ]
        filters = {
            a: AllSearchFilter[Secret]() for a in (Action.CREATE, Action.UPDATE, Action.DELETE)
        }
        results = await service.apply_batch(ops, filters, user_id=user.id)
        assert results[0] is not None and results[0].code == "B2"
        assert results[1] is not None and results[1].description == "updated"
        assert results[2] is None

    async def test_batch_denied_when_action_filter_none(
        self, service: SecretService, session: AsyncSession
    ) -> None:
        from pydantic import SecretStr

        user = await _seed_user(session)
        ops = [SecretBatchCreate(data=SecretCreate(code="BD", value=SecretStr("v")))]
        with pytest.raises(BatchPermissionDeniedError):
            await service.apply_batch(ops, {Action.CREATE: None}, user_id=user.id)


class TestCountAndSearch:
    async def test_count_and_search(self, service: SecretService, session: AsyncSession) -> None:
        from pydantic import SecretStr

        user = await _seed_user(session)
        for i in range(3):
            await service.create(SecretCreate(code=f"C{i}", value=SecretStr("v")), user_id=user.id)
        assert await service.count() == 3
        secrets, nxt = await service.search_secrets(limit=2)
        assert len(secrets) == 2
        assert nxt is not None
        rest, nxt2 = await service.search_secrets(cursor=nxt, limit=2)
        assert len(rest) == 1
        assert nxt2 is None


class TestSecretSchemaValidation:
    """Pure schema-level validation for SecretCreate/SecretUpdate code field."""

    def test_create_rejects_whitespace_only_code(self) -> None:
        from pydantic import SecretStr, ValidationError

        with pytest.raises(ValidationError):
            SecretCreate(code="   ", value=SecretStr("v"))

    def test_update_none_code_passes_through(self) -> None:
        assert SecretUpdate().code is None

    def test_update_rejects_whitespace_only_code(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            SecretUpdate(code="   ")

    def test_update_rejects_invalid_code_chars(self) -> None:
        with pytest.raises(ValueError, match="letters, digits"):
            SecretUpdate(code="bad!")
