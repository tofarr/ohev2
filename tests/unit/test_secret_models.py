"""Unit tests for the Secret and StaticSecretDetail ORM models (DB-backed)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.secret.secret_models import (
    Secret,
    SecretType,
    StaticSecretDetail,
)
from openhands.ev2.user.user_models import User


async def _seed_user(
    session: AsyncSession, *, username: str = "su", email: str = "s@example.com"
) -> User:
    user = User(email=email, username=username)
    session.add(user)
    await session.flush()
    return user


class TestSecretModel:
    async def test_create_secret_defaults(self, session: AsyncSession) -> None:
        secret = Secret(code="API_KEY")
        session.add(secret)
        await session.flush()
        await session.refresh(secret)
        assert isinstance(secret.id, uuid.UUID)
        assert secret.code == "API_KEY"
        assert secret.type == SecretType.STATIC
        assert secret.description is None
        assert secret.creator_id is None
        assert secret.created_at is not None
        assert secret.updated_at is not None

    async def test_code_is_unique(self, session: AsyncSession) -> None:
        session.add(Secret(code="DUP"))
        await session.flush()
        session.add(Secret(code="DUP"))
        with pytest.raises(IntegrityError):
            await session.flush()
        await session.rollback()

    async def test_description_round_trips(self, session: AsyncSession) -> None:
        secret = Secret(code="WITH_DESC", description="db password")
        session.add(secret)
        await session.flush()
        await session.refresh(secret)
        assert secret.description == "db password"

    async def test_creator_id_round_trips(self, session: AsyncSession) -> None:
        user = await _seed_user(session)
        secret = Secret(code="WITH_USER", creator_id=user.id)
        session.add(secret)
        await session.flush()
        await session.refresh(secret)
        assert secret.creator_id == user.id

    async def test_user_delete_sets_creator_id_null(self, session: AsyncSession) -> None:
        user = await _seed_user(session)
        secret = Secret(code="CASC_USER", creator_id=user.id)
        session.add(secret)
        await session.flush()
        secret_id = secret.id
        await session.delete(user)
        await session.flush()
        # Expunge stale cached objects so the next select hits the DB.
        session.expunge_all()
        found = (await session.execute(select(Secret).where(Secret.id == secret_id))).scalar_one()
        assert found.creator_id is None


class TestStaticSecretDetailModel:
    async def test_detail_is_one_to_one(self, session: AsyncSession) -> None:
        secret = Secret(code="DET_UNIQ")
        session.add(secret)
        await session.flush()
        session.add(StaticSecretDetail(secret_id=secret.id, value="enc-ciphertext"))
        await session.flush()
        session.add(StaticSecretDetail(secret_id=secret.id, value="enc-ciphertext-2"))
        with pytest.raises(IntegrityError):
            await session.flush()
        await session.rollback()

    async def test_secret_delete_cascades_to_detail(self, session: AsyncSession) -> None:
        secret = Secret(code="DET_CASC")
        session.add(secret)
        await session.flush()
        detail = StaticSecretDetail(secret_id=secret.id, value="enc-ciphertext")
        session.add(detail)
        await session.flush()
        detail_id = detail.id
        await session.delete(secret)
        await session.flush()
        found = (
            await session.execute(
                select(StaticSecretDetail).where(StaticSecretDetail.id == detail_id)
            )
        ).scalar_one_or_none()
        assert found is None
