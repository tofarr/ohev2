"""Unit tests for the Secret and RoleSecretPermission ORM models (DB-backed)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.role.role_models import Role
from openhands.ev2.secret.secret_models import RoleSecretPermission, Secret
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
        user = await _seed_user(session)
        secret = Secret(code="API_KEY", value="enc-ciphertext", user_id=user.id)
        session.add(secret)
        await session.flush()
        await session.refresh(secret)
        assert isinstance(secret.id, uuid.UUID)
        assert secret.code == "API_KEY"
        assert secret.value == "enc-ciphertext"
        assert secret.description is None
        assert secret.user_id == user.id
        assert secret.created_at is not None
        assert secret.updated_at is not None

    async def test_code_is_unique(self, session: AsyncSession) -> None:
        user = await _seed_user(session)
        session.add(Secret(code="DUP", value="v1", user_id=user.id))
        await session.flush()
        session.add(Secret(code="DUP", value="v2", user_id=user.id))
        with pytest.raises(IntegrityError):
            await session.flush()
        await session.rollback()

    async def test_description_round_trips(self, session: AsyncSession) -> None:
        user = await _seed_user(session)
        secret = Secret(code="WITH_DESC", value="v", user_id=user.id, description="db password")
        session.add(secret)
        await session.flush()
        await session.refresh(secret)
        assert secret.description == "db password"

    async def test_user_id_fk_cascade_on_user_delete(self, session: AsyncSession) -> None:
        user = await _seed_user(session)
        secret = Secret(code="CASC", value="v", user_id=user.id)
        session.add(secret)
        await session.flush()
        secret_id = secret.id
        await session.delete(user)
        await session.flush()
        # The secret row must be gone (FK ondelete=CASCADE).
        found = (
            await session.execute(select(Secret).where(Secret.id == secret_id))
        ).scalar_one_or_none()
        assert found is None


class TestRoleSecretPermissionModel:
    async def _seed_role_secret_permission_user(
        self, session: AsyncSession
    ) -> tuple[Role, Secret, User]:
        user = await _seed_user(session)
        role = Role(name="r-" + uuid.uuid4().hex[:8])
        secret = Secret(code="S_" + uuid.uuid4().hex[:6], value="v", user_id=user.id)
        session.add(role)
        session.add(secret)
        await session.flush()
        return role, secret, user

    async def test_create_grant_defaults(self, session: AsyncSession) -> None:
        role, secret, _ = await self._seed_role_secret_permission_user(session)
        link = RoleSecretPermission(role_id=role.id, secret_id=secret.id)
        session.add(link)
        await session.flush()
        await session.refresh(link)
        assert isinstance(link.id, uuid.UUID)
        assert link.role_id == role.id
        assert link.secret_id == secret.id
        assert link.read_enabled is False
        assert link.update_enabled is False
        assert link.delete_enabled is False
        assert link.created_at is not None

    async def test_grant_flags_round_trip(self, session: AsyncSession) -> None:
        role, secret, _ = await self._seed_role_secret_permission_user(session)
        link = RoleSecretPermission(
            role_id=role.id,
            secret_id=secret.id,
            read_enabled=True,
            update_enabled=True,
            delete_enabled=False,
        )
        session.add(link)
        await session.flush()
        await session.refresh(link)
        assert link.read_enabled is True
        assert link.update_enabled is True
        assert link.delete_enabled is False

    async def test_role_secret_permission_pair_is_unique(self, session: AsyncSession) -> None:
        role, secret, _ = await self._seed_role_secret_permission_user(session)
        session.add(RoleSecretPermission(role_id=role.id, secret_id=secret.id, read_enabled=True))
        await session.flush()
        session.add(RoleSecretPermission(role_id=role.id, secret_id=secret.id, read_enabled=False))
        with pytest.raises(IntegrityError):
            await session.flush()
        await session.rollback()

    async def test_cascade_delete_secret_removes_grants(self, session: AsyncSession) -> None:
        role, secret, _ = await self._seed_role_secret_permission_user(session)
        link = RoleSecretPermission(role_id=role.id, secret_id=secret.id, read_enabled=True)
        session.add(link)
        await session.flush()
        link_id = link.id
        await session.delete(secret)
        await session.flush()
        found = (
            await session.execute(
                select(RoleSecretPermission).where(RoleSecretPermission.id == link_id)
            )
        ).scalar_one_or_none()
        assert found is None
