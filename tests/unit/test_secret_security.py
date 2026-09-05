"""Unit tests for the secret permission policy and its search filter."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.role.role_models import Role, UserRole
from openhands.ev2.secret.secret_models import RoleSecretPermission, Secret, UserSecretPermission
from openhands.ev2.secret.secret_security import SecretAccess, SecretAccessFilter
from openhands.ev2.security.security_models import Action, Permitted
from openhands.ev2.user.user_models import User
from openhands.ev2.util.search_filter import AllSearchFilter, NoneSearchFilter


async def _seed_grant(
    session: AsyncSession,
    *,
    read: bool = False,
    update: bool = False,
    delete: bool = False,
) -> tuple[User, Secret, Role]:
    user = User(email="sec@example.com", username="sec")
    role = Role(name="r-" + uuid.uuid4().hex[:8])
    session.add(user)
    session.add(role)
    await session.flush()
    secret = Secret(code="S_" + uuid.uuid4().hex[:6], value="v")
    session.add(secret)
    await session.flush()
    session.add(UserRole(role_id=role.id, user_id=user.id))
    session.add(
        RoleSecretPermission(
            role_id=role.id,
            secret_id=secret.id,
            read_enabled=read,
            update_enabled=update,
            delete_enabled=delete,
        )
    )
    await session.flush()
    return user, secret, role


class TestSecretAccessReduction:
    def test_create_yields_all_filter(self) -> None:
        filt = SecretAccess().to_search_filter(uuid.uuid4(), Action.CREATE)
        assert isinstance(filt, AllSearchFilter)

    def test_anonymous_read_yields_none_filter(self) -> None:
        filt = SecretAccess().to_search_filter(None, Action.READ)
        assert isinstance(filt, NoneSearchFilter)

    def test_read_yields_read_flag_filter(self) -> None:
        uid = uuid.uuid4()
        filt = SecretAccess().to_search_filter(uid, Action.READ)
        assert isinstance(filt, SecretAccessFilter)
        assert filt.flag == "read_enabled"
        assert filt.user_id == uid

    def test_search_uses_read_flag(self) -> None:
        filt = SecretAccess().to_search_filter(uuid.uuid4(), Action.SEARCH)
        assert isinstance(filt, SecretAccessFilter)
        assert filt.flag == "read_enabled"

    def test_update_yields_update_flag(self) -> None:
        filt = SecretAccess().to_search_filter(uuid.uuid4(), Action.UPDATE)
        assert isinstance(filt, SecretAccessFilter)
        assert filt.flag == "update_enabled"

    def test_delete_yields_delete_flag(self) -> None:
        filt = SecretAccess().to_search_filter(uuid.uuid4(), Action.DELETE)
        assert isinstance(filt, SecretAccessFilter)
        assert filt.flag == "delete_enabled"

    def test_matches_is_permissive(self) -> None:
        # In-memory matches is intentionally permissive; SQL is authoritative.
        filt = SecretAccessFilter(user_id=uuid.uuid4(), flag="read_enabled")
        assert filt.matches(Secret(code="x", value="v")) is True


class TestSecretAccessFilterSql:
    async def test_read_filter_admits_only_granted(self, session: AsyncSession) -> None:
        user, secret, _ = await _seed_grant(session, read=True)
        # An ungranted secret must be excluded.
        other = Secret(code="OTHER", value="v")
        session.add(other)
        await session.flush()

        filt = SecretAccessFilter(user_id=user.id, flag="read_enabled")
        stmt = filt.filter_sql(select(Secret).order_by(Secret.code))
        result = (await session.execute(stmt)).scalars().all()
        ids = {s.id for s in result}
        assert secret.id in ids
        assert other.id not in ids

    async def test_read_filter_excludes_when_flag_disabled(self, session: AsyncSession) -> None:
        user, secret, _ = await _seed_grant(session, read=False, update=True)
        filt = SecretAccessFilter(user_id=user.id, flag="read_enabled")
        stmt = filt.filter_sql(select(Secret))
        result = (await session.execute(stmt)).scalars().all()
        assert secret.id not in {s.id for s in result}

    async def test_update_filter_admits_update_grant(self, session: AsyncSession) -> None:
        user, secret, _ = await _seed_grant(session, update=True)
        filt = SecretAccessFilter(user_id=user.id, flag="update_enabled")
        stmt = filt.filter_sql(select(Secret))
        result = (await session.execute(stmt)).scalars().all()
        assert secret.id in {s.id for s in result}

    async def test_filter_excludes_other_users(self, session: AsyncSession) -> None:
        _user, secret, _ = await _seed_grant(session, read=True)
        filt = SecretAccessFilter(user_id=uuid.uuid4(), flag="read_enabled")
        stmt = filt.filter_sql(select(Secret))
        result = (await session.execute(stmt)).scalars().all()
        assert secret.id not in {s.id for s in result}

    async def test_read_filter_admits_direct_user_grant(self, session: AsyncSession) -> None:
        user = User(email="direct@example.com", username="direct")
        secret = Secret(code="DIRECT_" + uuid.uuid4().hex[:6], value="v")
        session.add(user)
        session.add(secret)
        await session.flush()
        session.add(UserSecretPermission(user_id=user.id, secret_id=secret.id, read_enabled=True))
        await session.flush()

        filt = SecretAccessFilter(user_id=user.id, flag="read_enabled")
        result = (await session.execute(filt.filter_sql(select(Secret)))).scalars().all()
        assert secret.id in {s.id for s in result}


class TestPermittedBypassesGrants:
    async def test_permitted_sees_all_secrets(self, session: AsyncSession) -> None:
        # Permitted.to_search_filter returns AllSearchFilter for every action,
        # so an admin role bypasses the role_secret_permissions grant table entirely.
        for action in (Action.READ, Action.UPDATE, Action.DELETE, Action.SEARCH, Action.CREATE):
            assert isinstance(Permitted().to_search_filter(uuid.uuid4(), action), AllSearchFilter)
