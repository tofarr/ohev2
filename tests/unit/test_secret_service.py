"""Unit tests for the SecretsService ABC and its default SqlSecretsService.

The service is app-scoped and provider-neutral: tests construct
``SqlSecretsService()`` directly and pass permission filters per call. DB
access goes through ``get_session_factory()``, which the ``engine`` fixture
binds to the per-test savepoint transaction.
"""

from __future__ import annotations

import uuid

import pytest
import pytest_asyncio
from pydantic import SecretStr, ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.encryption.encryption_service import EncryptionService, get_encryption_service
from openhands.ev2.secret.secret_models import Secret, SecretType
from openhands.ev2.secret.secret_schemas import (
    SecretBatchCreate,
    SecretBatchDelete,
    SecretBatchOp,
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
    SecretValueNotFoundError,
    SecretValueTypeError,
    resolve_secrets_service_class,
)
from openhands.ev2.secret.sql_secrets_models import SqlSecret, SqlStaticSecretDetail
from openhands.ev2.secret.sql_secrets_service import SqlSecretsService
from openhands.ev2.security.security_models import Action
from openhands.ev2.user.user_models import User
from openhands.ev2.util.search_filter import ALL, NONE, SearchFilter


@pytest.fixture
def enc() -> EncryptionService:
    return get_encryption_service()


@pytest_asyncio.fixture
async def service(session: AsyncSession) -> SqlSecretsService:
    """The default SQL-backed service, bound to the per-test savepoint harness.

    The service manages its own sessions via ``get_session_factory()``; the
    ``session`` fixture dependency ensures the test env + savepoint
    transaction are in place even for tests that never touch ``session``
    directly.
    """
    return SqlSecretsService()


async def _seed_user(session: AsyncSession, *, n: int = 0) -> User:
    user = User(email=f"s{n}@example.com", username=f"su{n}")
    session.add(user)
    await session.flush()
    return user


async def _static_detail(
    session: AsyncSession, secret_id: uuid.UUID
) -> SqlStaticSecretDetail | None:
    # populate_existing: the service writes through its own session, so this
    # session's identity map may hold a stale copy of the detail row.
    result = await session.execute(
        select(SqlStaticSecretDetail)
        .where(SqlStaticSecretDetail.secret_id == secret_id)
        .execution_options(populate_existing=True)
    )
    return result.scalar_one_or_none()


class TestCreate:
    async def test_create_encrypts_value(
        self, service: SqlSecretsService, session: AsyncSession, enc: EncryptionService
    ) -> None:
        user = await _seed_user(session)
        secret = await service.create_secret(
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
        self, service: SqlSecretsService, session: AsyncSession
    ) -> None:
        user = await _seed_user(session)
        await service.create_secret(
            SecretCreate(code="DUP", value=SecretStr("v")), creator_id=user.id
        )
        with pytest.raises(SecretCodeConflictError):
            await service.create_secret(
                SecretCreate(code="DUP", value=SecretStr("v2")), creator_id=user.id
            )

    async def test_create_scope_denied(
        self, service: SqlSecretsService, session: AsyncSession
    ) -> None:
        user = await _seed_user(session)
        with pytest.raises(SecretPermissionScopeError):
            await service.create_secret(
                SecretCreate(code="X", value=SecretStr("v")),
                creator_id=user.id,
                perm_filter=NONE,
            )


class TestRead:
    async def test_get_returns_secret(
        self, service: SqlSecretsService, session: AsyncSession
    ) -> None:
        user = await _seed_user(session)
        secret = await service.create_secret(
            SecretCreate(code="G", value=SecretStr("plain")), creator_id=user.id
        )
        fetched = await service.get_secret(secret.id)
        assert fetched.id == secret.id

    async def test_get_missing_raises(self, service: SqlSecretsService) -> None:
        with pytest.raises(SecretNotFoundError):
            await service.get_secret(uuid.uuid4())

    async def test_get_out_of_scope_raises(
        self, service: SqlSecretsService, session: AsyncSession
    ) -> None:
        user = await _seed_user(session)
        secret = await service.create_secret(
            SecretCreate(code="OOS", value=SecretStr("v")), creator_id=user.id
        )
        with pytest.raises(SecretNotFoundError):
            await service.get_secret(secret.id, perm_filter=NONE)

    async def test_get_secrets_positional(
        self, service: SqlSecretsService, session: AsyncSession
    ) -> None:
        user = await _seed_user(session)
        a = await service.create_secret(
            SecretCreate(code="P_A", value=SecretStr("a")), creator_id=user.id
        )
        results = await service.get_secrets([a.id, uuid.uuid4()])
        assert results[0] is not None and results[0].code == "P_A"
        assert results[1] is None
        assert await service.get_secrets([]) == []

    async def test_secret_read_omits_value(
        self, service: SqlSecretsService, session: AsyncSession
    ) -> None:
        user = await _seed_user(session)
        secret = await service.create_secret(
            SecretCreate(code="R", value=SecretStr("reveal-me")), creator_id=user.id
        )
        read = SecretRead.model_validate(secret)
        assert read.code == "R"
        assert read.type == SecretType.STATIC
        # SecretRead must not carry a value field at all.
        assert "value" not in SecretRead.model_fields


class TestUpdate:
    async def test_update_value_re_encrypts(
        self, service: SqlSecretsService, session: AsyncSession, enc: EncryptionService
    ) -> None:
        user = await _seed_user(session)
        secret = await service.create_secret(
            SecretCreate(code="U", value=SecretStr("old")), creator_id=user.id
        )
        detail = await _static_detail(session, secret.id)
        assert detail is not None
        old_cipher = detail.value
        await service.update_secret(secret.id, SecretUpdate(value=SecretStr("new")))
        refreshed = await _static_detail(session, secret.id)
        assert refreshed is not None
        assert refreshed.value != old_cipher
        assert enc.decrypt_value(refreshed.value) == "new"

    async def test_update_code_conflict(
        self, service: SqlSecretsService, session: AsyncSession
    ) -> None:
        user = await _seed_user(session)
        await service.create_secret(
            SecretCreate(code="KEEP", value=SecretStr("v")), creator_id=user.id
        )
        other = await service.create_secret(
            SecretCreate(code="ORIG", value=SecretStr("v")), creator_id=user.id
        )
        with pytest.raises(SecretCodeConflictError):
            await service.update_secret(other.id, SecretUpdate(code="KEEP"))

    async def test_update_missing_raises(self, service: SqlSecretsService) -> None:
        with pytest.raises(SecretNotFoundError):
            await service.update_secret(uuid.uuid4(), SecretUpdate(code="x"))

    async def test_update_value_on_oauth_raises_type_error(
        self, service: SqlSecretsService, session: AsyncSession
    ) -> None:
        secret = SqlSecret(code="OAUTH_SECRET", type="oauth")  # type: ignore[arg-type]
        session.add(secret)
        await session.flush()
        await session.refresh(secret)
        with pytest.raises(SecretValueTypeError):
            await service.update_secret(secret.id, SecretUpdate(value=SecretStr("v")))

    async def test_update_value_recreates_missing_detail(
        self, service: SqlSecretsService, session: AsyncSession, enc: EncryptionService
    ) -> None:
        """A static secret whose detail row vanished gets a fresh one on value update."""
        user = await _seed_user(session)
        secret = await service.create_secret(
            SecretCreate(code="READD", value=SecretStr("v")), creator_id=user.id
        )
        detail = await _static_detail(session, secret.id)
        assert detail is not None
        await session.delete(detail)
        await session.flush()
        await service.update_secret(secret.id, SecretUpdate(value=SecretStr("v2")))
        recreated = await _static_detail(session, secret.id)
        assert recreated is not None
        assert enc.decrypt_value(recreated.value) == "v2"


class TestDelete:
    async def test_delete_removes(self, service: SqlSecretsService, session: AsyncSession) -> None:
        user = await _seed_user(session)
        secret = await service.create_secret(
            SecretCreate(code="DEL", value=SecretStr("v")), creator_id=user.id
        )
        await service.delete_secret(secret.id)
        with pytest.raises(SecretNotFoundError):
            await service.get_secret(secret.id)

    async def test_delete_missing_raises(self, service: SqlSecretsService) -> None:
        with pytest.raises(SecretNotFoundError):
            await service.delete_secret(uuid.uuid4())


def _all_actions() -> dict[Action, SearchFilter[Secret]]:
    """Grant filters for every batch action."""
    return dict.fromkeys((Action.CREATE, Action.UPDATE, Action.DELETE), ALL)


class TestBatch:
    async def test_batch_mixed_ops(self, service: SqlSecretsService, session: AsyncSession) -> None:
        user = await _seed_user(session)
        created = await service.create_secret(
            SecretCreate(code="B1", value=SecretStr("v")), creator_id=user.id
        )
        ops: list[SecretBatchOp] = [
            SecretBatchCreate(data=SecretCreate(code="B2", value=SecretStr("v2"))),
            SecretBatchUpdate(id=created.id, data=SecretUpdate(description="updated")),
            SecretBatchDelete(id=created.id),
        ]
        filters = _all_actions()
        results = await service.apply_batch(ops, filters, creator_id=user.id)
        assert results[0] is not None and results[0].code == "B2"
        assert results[1] is not None and results[1].description == "updated"
        assert results[2] is None

    async def test_batch_denied_when_action_filter_none(
        self, service: SqlSecretsService, session: AsyncSession
    ) -> None:
        user = await _seed_user(session)
        ops: list[SecretBatchOp] = [
            SecretBatchCreate(data=SecretCreate(code="BD", value=SecretStr("v")))
        ]
        filters: dict[Action, SearchFilter[Secret] | None] = {Action.CREATE: None}
        with pytest.raises(BatchPermissionDeniedError):
            await service.apply_batch(ops, filters, creator_id=user.id)

    async def test_batch_rolls_back_on_failure(
        self, service: SqlSecretsService, session: AsyncSession
    ) -> None:
        """A failing op rolls back the whole batch (atomic, no partial application)."""
        user = await _seed_user(session)
        existing = await service.create_secret(
            SecretCreate(code="TAKEN", value=SecretStr("v")), creator_id=user.id
        )
        ops: list[SecretBatchOp] = [
            SecretBatchCreate(data=SecretCreate(code="FIRST", value=SecretStr("v"))),
            SecretBatchCreate(data=SecretCreate(code="TAKEN", value=SecretStr("v"))),
        ]
        with pytest.raises(SecretCodeConflictError):
            await service.apply_batch(ops, _all_actions(), creator_id=user.id)
        # The first op in the batch must not survive the second op's failure.
        codes = {s.code for s in await service.list_secrets()}
        assert codes == {existing.code}

    async def test_batch_unknown_op_raises(self, service: SqlSecretsService) -> None:
        with pytest.raises(TypeError, match="Unknown secret batch op"):
            await service.apply_batch([object()], _all_actions(), creator_id=uuid.uuid4())  # type: ignore[list-item]


class TestCountAndSearch:
    async def test_count_and_search(
        self, service: SqlSecretsService, session: AsyncSession
    ) -> None:
        user = await _seed_user(session)
        for i in range(3):
            await service.create_secret(
                SecretCreate(code=f"C{i}", value=SecretStr("v")), creator_id=user.id
            )
        assert await service.count() == 3
        secrets, nxt = await service.search_secrets(limit=2)
        assert len(secrets) == 2
        assert nxt is not None
        rest, nxt2 = await service.search_secrets(cursor=nxt, limit=2)
        assert len(rest) == 1
        assert nxt2 is None


class TestValueReveal:
    """Reveal requires both read-access and value-reveal filters."""

    async def test_reveal_returns_plaintext(
        self, service: SqlSecretsService, session: AsyncSession
    ) -> None:
        user = await _seed_user(session)
        secret = await service.create_secret(
            SecretCreate(code="RV", value=SecretStr("reveal-me")), creator_id=user.id
        )
        read = await service.get_secret_value(secret.id, read_filter=ALL, value_filter=ALL)
        assert read.value == "reveal-me"
        assert read.code == "RV"
        assert read.type.value == "static"

    async def test_reveal_denied_without_read_access(
        self, service: SqlSecretsService, session: AsyncSession
    ) -> None:
        user = await _seed_user(session)
        secret = await service.create_secret(
            SecretCreate(code="NO_READ", value=SecretStr("v")), creator_id=user.id
        )
        with pytest.raises(SecretValueNotFoundError):
            await service.get_secret_value(secret.id, read_filter=NONE, value_filter=ALL)

    async def test_reveal_denied_without_value_permission(
        self, service: SqlSecretsService, session: AsyncSession
    ) -> None:
        user = await _seed_user(session)
        secret = await service.create_secret(
            SecretCreate(code="NO_VAL", value=SecretStr("v")), creator_id=user.id
        )
        with pytest.raises(SecretValueNotFoundError):
            await service.get_secret_value(secret.id, read_filter=ALL, value_filter=NONE)

    async def test_reveal_missing_detail_raises(
        self, service: SqlSecretsService, session: AsyncSession
    ) -> None:
        # A static secret with no detail row is a data integrity break.
        secret = SqlSecret(code="NO_DETAIL")
        session.add(secret)
        await session.flush()
        await session.refresh(secret)
        with pytest.raises(SecretValueNotFoundError):
            await service.get_secret_value(secret.id, read_filter=ALL, value_filter=ALL)

    async def test_reveal_oauth_has_no_value(
        self, service: SqlSecretsService, session: AsyncSession
    ) -> None:
        secret = SqlSecret(code="OAUTH_ND", type="oauth")  # type: ignore[arg-type]
        session.add(secret)
        await session.flush()
        await session.refresh(secret)
        with pytest.raises(SecretValueNotFoundError):
            await service.get_secret_value(secret.id, read_filter=ALL, value_filter=ALL)

    async def test_get_secret_values_positional(
        self, service: SqlSecretsService, session: AsyncSession
    ) -> None:
        user = await _seed_user(session)
        a = await service.create_secret(
            SecretCreate(code="GM_A", value=SecretStr("a")), creator_id=user.id
        )
        b = await service.create_secret(
            SecretCreate(code="GM_B", value=SecretStr("b")), creator_id=user.id
        )
        results = await service.get_secret_values(
            [a.id, b.id, uuid.uuid4()], read_filter=ALL, value_filter=ALL
        )
        assert results[0] is not None and results[0].value == "a"
        assert results[1] is not None and results[1].value == "b"
        assert results[2] is None
        assert await service.get_secret_values([], read_filter=ALL, value_filter=ALL) == []

    async def test_search_secret_values_skips_valueless(
        self, service: SqlSecretsService, session: AsyncSession
    ) -> None:
        user = await _seed_user(session)
        await service.create_secret(
            SecretCreate(code="SV1", value=SecretStr("one")), creator_id=user.id
        )
        oauth = SqlSecret(code="SV_OAUTH", type="oauth")  # type: ignore[arg-type]
        session.add(oauth)
        await session.flush()
        items, next_cursor = await service.search_secret_values(read_filter=ALL, value_filter=ALL)
        assert next_cursor is None
        assert [item.value for item in items] == ["one"]


class TestServiceLifecycle:
    async def test_async_context_manager(self, service: SqlSecretsService) -> None:
        async with service as entered:
            assert entered is service

    def test_resolve_secrets_service_class(self) -> None:
        cls = resolve_secrets_service_class(
            "openhands.ev2.secret.sql_secrets_service.SqlSecretsService"
        )
        assert cls is SqlSecretsService

    def test_resolve_rejects_non_subclass(self) -> None:
        with pytest.raises(TypeError, match="not a SecretsService subclass"):
            resolve_secrets_service_class("openhands.ev2.secret.sql_secrets_models.SqlSecret")

    def test_resolve_rejects_bad_names(self) -> None:
        with pytest.raises(ValueError, match="Invalid secrets_service class name"):
            resolve_secrets_service_class("NoDots")
        with pytest.raises(ValueError, match="Cannot import secrets_service module"):
            resolve_secrets_service_class("does.not.Exist")


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
