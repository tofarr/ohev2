"""Unit tests for the api_key permission policy and its search filter."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.api_key.api_key_security import ApiKeyAccess, ApiKeyAccessFilter
from openhands.ev2.auth.auth_models import ApiKey
from openhands.ev2.security.security_models import Action, Permitted
from openhands.ev2.util.search_filter import AllSearchFilter, NoneSearchFilter


class TestApiKeyAccessReduction:
    def test_anonymous_denied(self) -> None:
        for action in Action:
            assert isinstance(ApiKeyAccess().to_search_filter(None, action), NoneSearchFilter)

    def test_create_yields_self_scoped_filter(self) -> None:
        uid = uuid.uuid4()
        filt = ApiKeyAccess().to_search_filter(uid, Action.CREATE)
        assert isinstance(filt, ApiKeyAccessFilter)
        assert filt.user_id == uid

    def test_all_actions_use_same_self_scope(self) -> None:
        uid = uuid.uuid4()
        for action in (Action.READ, Action.SEARCH, Action.UPDATE, Action.DELETE, Action.CREATE):
            filt = ApiKeyAccess().to_search_filter(uid, action)
            assert isinstance(filt, ApiKeyAccessFilter)
            assert filt.user_id == uid


class TestApiKeyAccessFilterMatches:
    def test_matches_own_key(self) -> None:
        uid = uuid.uuid4()
        filt = ApiKeyAccessFilter[ApiKey](user_id=uid)
        own = ApiKey(key_hash="x" * 64, prefix="oh_x", user_id=uid, enabled=True, expires_at=None)
        assert filt.matches(own) is True

    def test_rejects_other_user_key(self) -> None:
        uid = uuid.uuid4()
        filt = ApiKeyAccessFilter[ApiKey](user_id=uid)
        other = ApiKey(
            key_hash="y" * 64,
            prefix="oh_y",
            user_id=uuid.uuid4(),
            enabled=True,
            expires_at=None,
        )
        assert filt.matches(other) is False


class TestApiKeyAccessFilterSql:
    async def test_filter_admits_only_own_keys(self, session: AsyncSession) -> None:
        from sqlalchemy import text

        uid = uuid.uuid4()
        other = uuid.uuid4()
        for u in (uid, other):
            await session.execute(
                text(
                    "INSERT INTO users (id, email, username, enabled) "
                    "VALUES (:id, :email, :username, true) "
                    "ON CONFLICT (id) DO NOTHING"
                ),
                {"id": u, "email": f"{u}@example.com", "username": str(u)},
            )
        own_key = ApiKey(
            key_hash="a" * 64, prefix="oh_a", user_id=uid, enabled=True, expires_at=None
        )
        other_key = ApiKey(
            key_hash="b" * 64, prefix="oh_b", user_id=other, enabled=True, expires_at=None
        )
        session.add_all([own_key, other_key])
        await session.flush()

        filt = ApiKeyAccessFilter[ApiKey](user_id=uid)
        stmt = filt.filter_sql(select(ApiKey).order_by(ApiKey.prefix))
        result = (await session.execute(stmt)).scalars().all()
        ids = {k.id for k in result}
        assert own_key.id in ids
        assert other_key.id not in ids

    async def test_permitted_bypasses_self_scope(self, session: AsyncSession) -> None:
        # Permitted.to_search_filter returns AllSearchFilter for every action,
        # so an admin role bypasses the self-scope entirely.
        for action in (Action.READ, Action.UPDATE, Action.DELETE, Action.SEARCH, Action.CREATE):
            assert isinstance(Permitted().to_search_filter(uuid.uuid4(), action), AllSearchFilter)
